/**
 * two-factor/totp-provider.ts
 *
 * TOTP / Authenticator-app provider (TwoFactorType 0).
 *
 * Conservative dual-track: reads/writes users.totp_secret and
 * users.totp_recovery_code (legacy columns), never touches two_factors table.
 * This preserves zero behavior change for existing TOTP users.
 *
 * H3 — Replay protection: after a successful verification the matched counter
 * value (floor(nowMs/30000) ± delta) is persisted in users.totp_last_counter.
 * Any subsequent code whose counter ≤ the stored value is rejected, closing the
 * ~90-second replay window where the same 6-digit code would otherwise be reusable.
 */

import type { Env, User } from '../../types';
import type { TwoFactorRow } from '../storage-two-factor-repo';
import { isTotpEnabled, verifyTotpToken } from '../../utils/totp';
import { updateTotpLastCounter } from '../storage-user-repo';
import type {
  ChallengeContext,
  TwoFactorProvider,
  TwoFactorTypeValue,
  VerifyContext,
} from './types';
import { TwoFactorType } from './types';

export class TotpTwoFactorProvider implements TwoFactorProvider {
  readonly type: TwoFactorTypeValue = TwoFactorType.Authenticator;

  isAvailable(_env: Env): boolean {
    // TOTP has no external dependencies — always available.
    return true;
  }

  isEnabledForUser(user: User, _twoFactorRows: TwoFactorRow[]): boolean {
    // Secret must exist AND the per-user enabled flag must be true.
    // totpEnabled=false means the user intentionally disabled TOTP (reversible).
    return isTotpEnabled(user.totpSecret) && user.totpEnabled !== false;
  }

  async buildChallenge(_ctx: ChallengeContext): Promise<null> {
    // Authenticator challenge carries no extra data per Bitwarden protocol.
    return null;
  }

  async verify(ctx: VerifyContext, token: string): Promise<boolean> {
    const { user, db } = ctx;
    const secret = user.totpSecret;
    // Only verify when both secret exists AND TOTP is actively enabled.
    if (!secret || !isTotpEnabled(secret) || user.totpEnabled === false) return false;

    // verifyTotpToken now returns the matched counter (number) or null on failure.
    const matchedCounter = await verifyTotpToken(secret, token);
    if (matchedCounter === null) return false;

    // H3 Replay protection: reject if this counter was already used.
    if (user.totpLastCounter !== null && matchedCounter <= user.totpLastCounter) {
      return false;
    }

    // Persist the matched counter before the caller issues tokens. This write is
    // intentionally placed inside verify() so that the counter is always committed
    // regardless of which code path the caller takes after a successful verify.
    await updateTotpLastCounter(db, user.id, matchedCounter);

    return true;
  }
}

export const totpProvider: TwoFactorProvider = new TotpTwoFactorProvider();
