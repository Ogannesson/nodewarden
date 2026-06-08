/**
 * two-factor/email-provider.ts
 *
 * Email OTP second-factor provider (TwoFactorType 1).
 *
 * Security implementation follows docs/MFA-SECURITY-CHECKLIST.md §3:
 * - 6-digit numeric code, 600-second TTL, max 3 attempts before token invalidation.
 * - Constant-time comparison (via XOR-accumulation timingSafeEqual).
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
  deleteTwoFactor,
} from '../storage-two-factor-repo';
import type {
  ChallengeContext,
  TwoFactorProvider,
  TwoFactorTypeValue,
  VerifyContext,
} from './types';
import { TwoFactorType } from './types';
import { isEmailSenderConfigured } from '../email-sender';
import { timingSafeEqual } from '../../utils/passkey';
import { safeWriteAuditEvent } from '../audit-events';
import { sha256Hex } from '../../utils/recovery-code';

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
  /** SHA-256 hex digest of the 6-digit code (never stored in plaintext). */
  code: string;
  /** Unix-epoch milliseconds at creation. */
  createdAt: number;
  /** Failed verification attempts so far. */
  attempts: number;
  /** The enrolled email this challenge is bound to (prevents enrollment-swap attacks). */
  targetEmail: string;
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

  /** Available only when the email sending stack is configured (MFA_EMAIL_FROM + at least one backend). */
  isAvailable(env: Env): boolean {
    return isEmailSenderConfigured(env);
  }

  /** Enabled for a user if they have an atype=1 enabled row in two_factors. */
  isEnabledForUser(_user: User, twoFactorRows: TwoFactorRow[]): boolean {
    return twoFactorRows.some(r => r.atype === EMAIL_ENROLLMENT_ATYPE && r.enabled);
  }

  /**
   * Announce the Email provider for the login challenge: TwoFactorProviders2["1"].
   *
   * IMPORTANT: this returns ONLY the masked destination — it does not generate,
   * store, or send a code. Code delivery is owned solely by the send-email-login
   * endpoint (handleSendEmailLogin), which the web client calls during the
   * challenge. (Bug fix: this method used to also generate + send a code, so every
   * login produced two emails and the first code was immediately overwritten by the
   * client-triggered send and thus invalid.)
   *
   * TwoFactorProviders2["1"] = { "Email": "u***@example.com" }
   */
  async buildChallenge(ctx: ChallengeContext): Promise<unknown> {
    const { twoFactorRows } = ctx;

    const enrollmentRow = twoFactorRows.find(r => r.atype === EMAIL_ENROLLMENT_ATYPE && r.enabled);
    if (!enrollmentRow) {
      throw new Error('Email 2FA not enrolled for this user');
    }
    const enrollment = JSON.parse(enrollmentRow.data) as EmailEnrollmentData;
    return { Email: maskEmail(enrollment.email) };
  }

  /**
   * Verify a submitted 6-digit code.
   * Returns true on success (and deletes the challenge row).
   * Returns false on wrong code or expired/exceeded-attempts challenge.
   *
   * Security: the attempt counter is incremented atomically via a single
   * conditional UPDATE…RETURNING, eliminating the TOCTOU race that existed
   * between the old SELECT + application-level increment + upsert pattern.
   * A concurrent second request will see the same post-increment state and
   * will be blocked if the limit is already reached.
   */
  async verify(ctx: VerifyContext, token: string): Promise<boolean> {
    const { user, db, env } = ctx;
    const normalized = String(token ?? '').trim();

    // Atomically increment the attempt counter and return the updated row.
    // If no row exists (already deleted or never created) result.results is
    // empty — fail closed without a second round-trip.
    const result = await db
      .prepare(
        `UPDATE two_factors
            SET data       = json_set(data, '$.attempts', json_extract(data, '$.attempts') + 1),
                updated_at = ?
          WHERE user_id = ?
            AND atype   = ?
          RETURNING data`,
      )
      .bind(new Date().toISOString(), user.id, EMAIL_LOGIN_CHALLENGE_ATYPE)
      .all<{ data: string }>();

    if (result.results.length === 0) {
      // Row was not present (already consumed or never created).
      return false;
    }

    let challenge: EmailChallenge;
    try {
      challenge = JSON.parse(result.results[0].data) as EmailChallenge;
    } catch {
      // Corrupt state — remove and reject.
      await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      return false;
    }

    // TTL check on the returned (post-increment) state.
    const ageMs = Date.now() - challenge.createdAt;
    if (ageMs > CODE_TTL_S * 1000) {
      await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      return false;
    }

    // The UPDATE already counted this attempt.  If the post-increment value
    // exceeds the limit, invalidate and reject.
    if (challenge.attempts > MAX_ATTEMPTS) {
      await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      return false;
    }

    // Constant-time comparison (attempt already counted; no second write on
    // mismatch — the incremented counter persists in the DB).
    const match = await constantTimeEqualStrings(await sha256Hex(normalized), challenge.code);

    if (!match) {
      // If this attempt was the last allowed one, clean up so the row does
      // not linger with a fully-exhausted counter.
      if (challenge.attempts >= MAX_ATTEMPTS) {
        await deleteTwoFactor(db, user.id, EMAIL_LOGIN_CHALLENGE_ATYPE);
      }
      return false;
    }

    // Success — consume the challenge (one-time use).
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
