/**
 * two-factor/totp-provider.ts
 *
 * TOTP / Authenticator-app provider (TwoFactorType 0).
 *
 * Conservative dual-track: reads/writes users.totp_secret and
 * users.totp_recovery_code (legacy columns), never touches two_factors table.
 * This preserves zero behavior change for existing TOTP users.
 */

import type { Env, User } from '../../types';
import type { TwoFactorRow } from '../storage-two-factor-repo';
import { isTotpEnabled, verifyTotpToken } from '../../utils/totp';
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
    const secret = ctx.user.totpSecret;
    // Only verify when both secret exists AND TOTP is actively enabled.
    if (!secret || !isTotpEnabled(secret) || ctx.user.totpEnabled === false) return false;
    return verifyTotpToken(secret, token);
  }
}

export const totpProvider: TwoFactorProvider = new TotpTwoFactorProvider();
