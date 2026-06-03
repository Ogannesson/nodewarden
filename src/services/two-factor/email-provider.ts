/**
 * two-factor/email-provider.ts
 *
 * Email OTP second-factor provider (TwoFactorType 1).
 *
 * Security implementation follows docs/MFA-SECURITY-CHECKLIST.md §3:
 * - 6-digit numeric code, 600-second TTL, max 3 attempts before token invalidation.
 * - Constant-time comparison (via HMAC-based timingSafeEqual).
 * - Send failures are thrown (never swallowed).
 * - Anti-enumeration: send-email-login always returns 200 regardless of user existence.
 * - Rate limiting delegated to the caller (RateLimitService.recordFailedLogin).
 *
 * Storage layout (two_factors table):
 *   atype=1  (TwoFactorType.Email)      enabled row: { email: string }
 *   atype=1002 (EMAIL_LOGIN_CHALLENGE_ATYPE) challenge row: EmailChallenge
 *
 * Masking: the 2FA challenge response exposes only a partially-masked email address
 * (matches Bitwarden TwoFactorProviders2["1"] = { "Email": "u***@e***.com" }).
 */

import type { Env, User } from '../../types';
import type { TwoFactorRow } from '../storage-two-factor-repo';
import {
  getTwoFactor,
  upsertTwoFactor,
  deleteTwoFactor,
} from '../storage-two-factor-repo';
import type {
  ChallengeContext,
  TwoFactorProvider,
  TwoFactorTypeValue,
  VerifyContext,
} from './types';
import { TwoFactorType } from './types';
import { buildEmailSenderFromEnv } from '../email-sender';
import { timingSafeEqual } from '../../utils/passkey';
import { safeWriteAuditEvent } from '../audit-events';

// ---------------------------------------------------------------------------
// Internal atype for challenge state
// ---------------------------------------------------------------------------

/** D1 atype for a pending Email login challenge (mirrors Vaultwarden 1002). */
export const EMAIL_LOGIN_CHALLENGE_ATYPE = 1002;

/** Enrollment row atype */
export const EMAIL_ENROLLMENT_ATYPE = TwoFactorType.Email; // 1

/** Code TTL in seconds (10 minutes, per checklist). */
export const CODE_TTL_S = 600;

/** Maximum failed attempts before the challenge is invalidated. */
export const MAX_ATTEMPTS = 3;

// ---------------------------------------------------------------------------
// Data shapes
// ---------------------------------------------------------------------------

/** Stored in two_factors.data for atype=1 (enrollment). */
interface EmailEnrollmentData {
  /** The verified target email address for this 2FA binding. */
  email: string;
}

/** Stored in two_factors.data for atype=1002 (login challenge). */
interface EmailChallenge {
  /** 6-digit numeric string. */
  code: string;
  /** Unix-epoch milliseconds at creation. */
  createdAt: number;
  /** Failed verification attempts so far. */
  attempts: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a cryptographically-random 6-digit numeric code. */
export function generateNumericCode(): string {
  // Rejection sampling for uniform distribution over [0, 1_000_000).
  const max = 1_000_000;
  const maxUnbiased = Math.floor(0x1_0000_0000 / max) * max;
  const buf = new Uint32Array(1);
  let value: number;
  do {
    crypto.getRandomValues(buf);
    value = buf[0];
  } while (value >= maxUnbiased);
  return (value % max).toString().padStart(6, '0');
}

/** Mask an email address: "user@example.com" → "u***@e***.com". */
export function maskEmail(email: string): string {
  const atIdx = email.lastIndexOf('@');
  if (atIdx <= 0) return '***';
  const local = email.slice(0, atIdx);
  const rest = email.slice(atIdx + 1); // e.g. "example.com"
  const domainDot = rest.lastIndexOf('.');
  // domain = "example", tldWithDot = ".com" (includes the dot)
  const domain = domainDot > 0 ? rest.slice(0, domainDot) : rest;
  const tldWithDot = domainDot > 0 ? rest.slice(domainDot) : '.???';
  return `${local[0]}***@${domain[0]}***${tldWithDot}`;
}

/** Constant-time string equality wrapper. */
async function constantTimeEqualStrings(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  return timingSafeEqual(enc.encode(a), enc.encode(b));
}

// ---------------------------------------------------------------------------
// EmailTwoFactorProvider
// ---------------------------------------------------------------------------

class EmailTwoFactorProvider implements TwoFactorProvider {
  readonly type: TwoFactorTypeValue = TwoFactorType.Email;

  /** Available only when RESEND_API_KEY + MFA_EMAIL_FROM are configured. */
  isAvailable(env: Env): boolean {
    return !!(env.RESEND_API_KEY && env.MFA_EMAIL_FROM);
  }

  /** Enabled for a user if they have an atype=1 enabled row in two_factors. */
  isEnabledForUser(_user: User, twoFactorRows: TwoFactorRow[]): boolean {
    return twoFactorRows.some(r => r.atype === EMAIL_ENROLLMENT_ATYPE && r.enabled);
  }

  /**
   * Build the login challenge: generate + store a code, send it, return masked email.
   * TwoFactorProviders2["1"] = { "Email": "u***@example.com" }
   */
  async buildChallenge(ctx: ChallengeContext): Promise<unknown> {
    const { user, env, db, twoFactorRows } = ctx;

    // Find enrollment row.
    const enrollmentRow = twoFactorRows.find(r => r.atype === EMAIL_ENROLLMENT_ATYPE && r.enabled);
    if (!enrollmentRow) {
      throw new Error('Email 2FA not enrolled for this user');
    }
    const enrollment = JSON.parse(enrollmentRow.data) as EmailEnrollmentData;
    const targetEmail = enrollment.email;

    // Generate code and store challenge (upsert — one active challenge per user).
    const code = generateNumericCode();
    const challenge: EmailChallenge = {
      code,
      createdAt: Date.now(),
      attempts: 0,
    };
    await upsertTwoFactor(db, {
      userId: user.id,
      atype: EMAIL_LOGIN_CHALLENGE_ATYPE,
      enabled: true,
      data: JSON.stringify(challenge),
      lastUsed: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Send the code — failure MUST throw (no silent swallowing).
    const sender = buildEmailSenderFromEnv(env);
    if (!sender) {
      throw new Error('Email sender not configured (RESEND_API_KEY / MFA_EMAIL_FROM missing)');
    }
    await sender.send({
      to: targetEmail,
      subject: 'Your NodeWarden verification code',
      text: [
        `Your NodeWarden verification code is: ${code}`,
        '',
        `This code expires in ${CODE_TTL_S / 60} minutes and can only be used once.`,
        'If you did not request this code, please secure your account immediately.',
      ].join('\n'),
      html: [
        `<p>Your NodeWarden verification code is: <strong>${code}</strong></p>`,
        `<p>This code expires in ${CODE_TTL_S / 60} minutes and can only be used once.</p>`,
        '<p>If you did not request this code, please secure your account immediately.</p>',
      ].join(''),
    });

    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'account.email2fa.code_sent',
      category: 'security',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
    });

    return { Email: maskEmail(targetEmail) };
  }

  /**
   * Verify a submitted 6-digit code.
   * Returns true on success (and deletes the challenge row).
   * Returns false on wrong code or expired/exceeded-attempts challenge.
   */
  async verify(ctx: VerifyContext, token: string): Promise<boolean> {
    const { user, db, env } = ctx;
    const normalized = String(token ?? '').trim();

    // Load the pending challenge row.
    const challengeRow = await getTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
    if (!challengeRow) return false;

    const challenge = JSON.parse(challengeRow.data) as EmailChallenge;

    // TTL check.
    const ageMs = Date.now() - challenge.createdAt;
    if (ageMs > CODE_TTL_S * 1000) {
      // Expired — delete and reject.
      await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      return false;
    }

    // Attempt limit check (before comparing, to prevent timing oracle).
    if (challenge.attempts >= MAX_ATTEMPTS) {
      await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      return false;
    }

    // Constant-time comparison.
    const match = await constantTimeEqualStrings(normalized, challenge.code);

    if (!match) {
      // Increment attempt counter; invalidate if limit reached.
      const newAttempts = challenge.attempts + 1;
      if (newAttempts >= MAX_ATTEMPTS) {
        await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      } else {
        await upsertTwoFactor(db, {
          ...challengeRow,
          data: JSON.stringify({ ...challenge, attempts: newAttempts }),
          updatedAt: new Date().toISOString(),
        });
      }
      return false;
    }

    // Success — delete the challenge (one-time use).
    await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);

    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'account.email2fa.verified',
      category: 'security',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
    });

    return true;
  }
}

export const emailProvider = new EmailTwoFactorProvider();

// Re-export types needed by the management endpoint handler
export type { EmailEnrollmentData, EmailChallenge };
