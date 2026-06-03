/**
 * two-factor/types.ts
 *
 * Core types for the multi-provider MFA abstraction layer.
 *
 * Design: each provider implements TwoFactorProvider; the registry
 * assembles them into a list. identity.ts drives challenge generation
 * and token verification through these interfaces — never hard-coded.
 */

import type { User, Env } from '../../types';
import type { TwoFactorRow } from '../storage-two-factor-repo';

// ---------------------------------------------------------------------------
// TwoFactorType values (mirrors Bitwarden / Vaultwarden enum)
// ---------------------------------------------------------------------------

export const TwoFactorType = {
  /** TOTP / authenticator app. NodeWarden stores this in users.totp_secret (legacy column). */
  Authenticator: 0,
  /** Email OTP. */
  Email: 1,
  /** Duo (enterprise, not implemented in this release). */
  Duo: 2,
  /** YubiKey OTP (YubiCloud). */
  YubiKey: 3,
  /** "Remember device" (trusted device token). Handled separately in identity.ts. */
  Remember: 5,
  /** WebAuthn / FIDO2 security key. */
  WebAuthn: 7,
  /** Recovery code (all providers share one recovery code). Handled separately. */
  RecoveryCode: 8,
} as const;

export type TwoFactorTypeValue = (typeof TwoFactorType)[keyof typeof TwoFactorType];

// ---------------------------------------------------------------------------
// Context objects passed into provider methods
// ---------------------------------------------------------------------------

/** Context available when building a login challenge (before token is known). */
export interface ChallengeContext {
  user: User;
  env: Env;
  db: D1Database;
  /** Rows from two_factors table for this user (pre-fetched by caller). */
  twoFactorRows: TwoFactorRow[];
  /**
   * The incoming HTTP request — used by WebAuthn to derive rpId and origin
   * from the Host header.  Optional; providers that don't need it may ignore it.
   */
  request?: Request;
}

/** Context available when verifying a submitted 2FA token. */
export interface VerifyContext {
  user: User;
  env: Env;
  db: D1Database;
  /** Rows from two_factors table for this user (pre-fetched by caller). */
  twoFactorRows: TwoFactorRow[];
  /** The incoming HTTP request (optional; available for providers that need it). */
  request?: Request;
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

/**
 * A TwoFactorProvider encapsulates one MFA method.
 *
 * Lifecycle:
 *   1. identity.ts calls `isAvailable(env)` — if false, skip this provider entirely.
 *   2. For the current user, `isEnabledForUser(user, rows)` — if false, not in challenge list.
 *   3. If the user needs a challenge, `buildChallenge(ctx)` fills TwoFactorProviders2[type].
 *   4. When user submits a token, `verify(ctx, token)` validates it.
 */
export interface TwoFactorProvider {
  /** The numeric Bitwarden TwoFactorType value for this provider. */
  readonly type: TwoFactorTypeValue;

  /**
   * True if this provider is available for use on this deployment.
   * Example: Email returns false if RESEND_API_KEY is not configured.
   * TOTP always returns true (no external dependency).
   */
  isAvailable(env: Env): boolean;

  /**
   * True if this provider is enabled for the given user.
   * Receives the pre-fetched two_factors rows (plus the full User object for
   * providers that use legacy columns, e.g. TOTP uses users.totp_secret).
   */
  isEnabledForUser(user: User, twoFactorRows: TwoFactorRow[]): boolean;

  /**
   * Build the TwoFactorProviders2[type] value to include in the login challenge.
   * For Authenticator(0) this is null. For WebAuthn(7) this is a
   * PublicKeyCredentialRequestOptions-style object.
   * May be async (e.g. WebAuthn needs to generate+store a challenge).
   */
  buildChallenge(ctx: ChallengeContext): Promise<unknown>;

  /**
   * Verify the submitted token for this provider.
   * Returns true on success, false on failure.
   * Side-effects (e.g. disable TOTP on recovery, update last_used) happen here.
   */
  verify(ctx: VerifyContext, token: string): Promise<boolean>;
}
