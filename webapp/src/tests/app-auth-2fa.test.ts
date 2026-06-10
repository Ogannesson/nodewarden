/**
 * app-auth.ts – 2FA provider 字符串/数字归一化回归测试
 *
 * 这组测试锁定服务端与前端之间的 TwoFactorProviders 形状契约：
 * 服务端发送字符串数组 ["0","7"]，前端必须能正确识别 WebAuthn provider 7 和 TOTP provider 0。
 *
 * 历史 bug：前端用 providers.includes(7)（数字）判断，而服务端发的是 "7"（字符串），
 * 导致 WebAuthn 分支永不命中，fallthrough 到 TOTP。
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// -----------------------------------------------------------------------
// Mock 所有 app-auth.ts 的外部依赖
// -----------------------------------------------------------------------

vi.mock('@/lib/api/auth', () => ({
  deriveLoginHashLocally: vi.fn(),
  loginWithPassword: vi.fn(),
  loginWithEmailCode: vi.fn(),
  sendEmailLoginCode: vi.fn().mockResolvedValue(undefined),
  createAuthedFetch: vi.fn(() => vi.fn()),
  getProfile: vi.fn(),
  loadProfileSnapshot: vi.fn(() => null),
  loadSession: vi.fn(() => null),
  refreshAccessToken: vi.fn(),
  recoverTwoFactor: vi.fn(),
  registerAccount: vi.fn(),
  unlockVaultKey: vi.fn(),
}));

vi.mock('@/lib/app-support', () => ({
  readInviteCodeFromUrl: vi.fn(() => null),
}));

vi.mock('@/lib/i18n', () => ({
  t: vi.fn((key: string) => key),
  translateServerError: vi.fn((_err: unknown, fallback: string) => fallback),
}));

import { performPasswordLogin, performUnlock } from '@/lib/app-auth';
import { deriveLoginHashLocally, loginWithPassword, sendEmailLoginCode, unlockVaultKey } from '@/lib/api/auth';
import type { SessionState } from '@/lib/types';

// -----------------------------------------------------------------------
// Mock 数据工厂
// -----------------------------------------------------------------------

const MOCK_MASTER_KEY = new Uint8Array(32).fill(1);
const MOCK_HASH = 'base64-hash==';

/** 服务端真实形状的 WebAuthn 2FA 挑战响应 */
function makeWebAuthnChallengeResponse(opts: {
  extraProviders?: string[];
  webAuthnData?: Record<string, unknown>;
} = {}) {
  return {
    TwoFactorProviders: ['0', '7', ...(opts.extraProviders ?? [])],
    TwoFactorProviders2: {
      '7': {
        challenge: 'dGVzdC1jaGFsbGVuZ2U=',
        allowCredentials: [{ type: 'public-key', id: 'cred-id-base64' }],
        rpId: 'example.com',
        status: 'ok',
        ...(opts.webAuthnData ?? {}),
      },
      '0': null,
    },
    error: 'invalid_grant',
  };
}

/** 只含 TOTP 的挑战响应（无 WebAuthn） */
function makeTotpOnlyChallengeResponse() {
  return {
    TwoFactorProviders: ['0'],
    TwoFactorProviders2: { '0': null },
    error: 'invalid_grant',
  };
}

/** 只含 Email 2FA 的挑战响应 */
function makeEmailOnlyChallengeResponse() {
  return {
    TwoFactorProviders: ['1'],
    TwoFactorProviders2: { '1': null },
    error: 'invalid_grant',
  };
}

/** 数字形式的 WebAuthn 挑战响应（旧服务端兼容） */
function makeNumericWebAuthnChallengeResponse() {
  return {
    TwoFactorProviders: [0, 7],
    TwoFactorProviders2: {
      '7': {
        challenge: 'dGVzdC1jaGFsbGVuZ2U=',
        allowCredentials: [],
        rpId: 'example.com',
        status: 'ok',
      },
      '0': null,
    },
    error: 'invalid_grant',
  };
}

// -----------------------------------------------------------------------
// beforeEach：重置所有 mock
// -----------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();

  // deriveLoginHashLocally 默认返回 mock 推导结果
  (deriveLoginHashLocally as ReturnType<typeof vi.fn>).mockResolvedValue({
    hash: MOCK_HASH,
    masterKey: MOCK_MASTER_KEY,
    kdfIterations: 600000,
  });

  // unlockVaultKey 默认成功
  (unlockVaultKey as ReturnType<typeof vi.fn>).mockResolvedValue({
    symEncKey: new Uint8Array(32),
    symMacKey: new Uint8Array(32),
  });

  // sendEmailLoginCode 默认成功（不实际发邮件）
  (sendEmailLoginCode as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
});

// -----------------------------------------------------------------------
// performPasswordLogin 测试套件
// -----------------------------------------------------------------------

describe('performPasswordLogin – WebAuthn 挑战识别', () => {
  it('服务端返回字符串 provider ["0","7"] → kind=webauthn，hasTotpFallback=true', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeWebAuthnChallengeResponse());

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('webauthn');
    if (result.kind === 'webauthn') {
      expect(result.pendingWebAuthn.hasTotpFallback).toBe(true);
      expect(result.pendingWebAuthn.webAuthnChallenge.challenge).toBe('dGVzdC1jaGFsbGVuZ2U=');
      expect(result.pendingWebAuthn.webAuthnChallenge.rpId).toBe('example.com');
      expect(result.pendingWebAuthn.webAuthnChallenge.allowCredentials).toHaveLength(1);
    }
  });

  it('服务端返回数字 provider [0, 7]（旧形状兼容）→ kind=webauthn', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeNumericWebAuthnChallengeResponse());

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('webauthn');
    if (result.kind === 'webauthn') {
      expect(result.pendingWebAuthn.hasTotpFallback).toBe(true);
    }
  });

  it('服务端只返回 ["0"]（仅 TOTP）→ kind=totp，不误判为 webauthn', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeTotpOnlyChallengeResponse());

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('totp');
  });

  it('服务端只返回 ["1"]（Email 2FA）→ kind=email（触发发码后返回 pendingEmail）', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmailOnlyChallengeResponse());

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    // Email-only（provider 1，无 TOTP/WebAuthn）→ kind=email
    expect(result.kind).toBe('email');
  });

  it('仅含 ["7"] 无 TOTP → kind=webauthn，hasTotpFallback=false', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue({
      TwoFactorProviders: ['7'],
      TwoFactorProviders2: {
        '7': {
          challenge: 'abc=',
          allowCredentials: [],
          rpId: 'example.com',
          status: 'ok',
        },
      },
      error: 'invalid_grant',
    });

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('webauthn');
    if (result.kind === 'webauthn') {
      expect(result.pendingWebAuthn.hasTotpFallback).toBe(false);
    }
  });

  it('服务端返回 TwoFactorProviders2 中 "7" 缺失 → 降级到 totp', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue({
      TwoFactorProviders: ['0', '7'],
      TwoFactorProviders2: {
        '0': null,
        // '7' 缺失
      },
      error: 'invalid_grant',
    });

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    // 没有 providers2['7'] 数据 → 无法构造 WebAuthn 挑战 → fallback 到 totp
    expect(result.kind).toBe('totp');
  });

  it('Email 2FA 挑战含大写 Email key → maskedEmail 取脱敏值（不 fallback 到完整邮箱）', async () => {
    // 回归守卫：服务端返回 TwoFactorProviders2["1"] = { Email: "u***@e***.com" }（大写 E，
    // Bitwarden 兼容）。前端必须读到脱敏值，而不是因读 p1['email']（小写）落空、
    // fallback 成用户输入的完整邮箱（泄露/UX bug）。
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue({
      TwoFactorProviders: ['1'],
      TwoFactorProviders2: { '1': { Email: 'u***@e***.com' } },
      error: 'invalid_grant',
    });

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('email');
    if (result.kind === 'email') {
      expect(result.pendingEmail.maskedEmail).toBe('u***@e***.com');
    }
  });
});

// -----------------------------------------------------------------------
// performUnlock 测试套件
// -----------------------------------------------------------------------

const MOCK_SESSION: SessionState = {
  email: 'user@example.com',
  accessToken: 'tok',
  refreshToken: 'refresh',
  authMode: 'token',
};

describe('performUnlock – WebAuthn 挑战识别', () => {
  it('服务端返回字符串 provider ["0","7"] → kind=webauthn，hasTotpFallback=true', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeWebAuthnChallengeResponse());

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('webauthn');
    if (result.kind === 'webauthn') {
      expect(result.pendingWebAuthn.hasTotpFallback).toBe(true);
      expect(result.pendingWebAuthn.webAuthnChallenge.challenge).toBe('dGVzdC1jaGFsbGVuZ2U=');
    }
  });

  it('服务端返回数字 provider [0, 7] → kind=webauthn', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeNumericWebAuthnChallengeResponse());

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('webauthn');
  });

  it('服务端只返回 ["0"] → kind=totp，不误判', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeTotpOnlyChallengeResponse());

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('totp');
  });

  it('服务端只返回 ["1"]（Email 2FA）→ kind=email', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmailOnlyChallengeResponse());

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('email');
  });
});

// -----------------------------------------------------------------------
// Bug #15 回归测试：TOTP + Email 同时启用时 Email fallback 可达
// -----------------------------------------------------------------------

/** TOTP + Email 同时存在的挑战响应（providers ['0','1']） */
function makeTotpWithEmailChallengeResponse() {
  return {
    TwoFactorProviders: ['0', '1'],
    TwoFactorProviders2: {
      '0': null,
      '1': { Email: 'u***@e***.com' },
    },
    error: 'invalid_grant',
  };
}

describe('performPasswordLogin – TOTP + Email 同时启用（Bug #15 回归）', () => {
  it('providers ["0","1"] → kind=totp，hasEmailFallback=true', async () => {
    // 场景：用户同时启用了 TOTP(0) 和 Email 2FA(1)；无 WebAuthn
    // 预期：走 TOTP 分支（优先级更高），但携带 hasEmailFallback=true
    // 修复前 bug：providerKeys.includes('1') && !providerKeys.includes('0') → false
    //             导致 email 分支完全不可达（用户被迫只能用 TOTP，无法切换 Email OTP）
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeTotpWithEmailChallengeResponse(),
    );

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('totp');
    if (result.kind === 'totp') {
      expect(result.pendingTotp.hasEmailFallback).toBe(true);
    }
  });

  it('providers ["0"] 无 Email → kind=totp，hasEmailFallback=false', async () => {
    // 只有 TOTP，无 Email fallback → hasEmailFallback 应为 false
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeTotpOnlyChallengeResponse(),
    );

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('totp');
    if (result.kind === 'totp') {
      expect(result.pendingTotp.hasEmailFallback).toBe(false);
    }
  });
});

describe('performUnlock – TOTP + Email 同时启用（Bug #15 回归）', () => {
  it('providers ["0","1"] → kind=totp，hasEmailFallback=true', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeTotpWithEmailChallengeResponse(),
    );

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('totp');
    if (result.kind === 'totp') {
      expect(result.pendingTotp.hasEmailFallback).toBe(true);
    }
  });

  it('providers ["0"] 无 Email → kind=totp，hasEmailFallback=false', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeTotpOnlyChallengeResponse(),
    );

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('totp');
    if (result.kind === 'totp') {
      expect(result.pendingTotp.hasEmailFallback).toBe(false);
    }
  });
});

// -----------------------------------------------------------------------
// WebAuthn 空 challenge 降级（dead-end 修复）
// -----------------------------------------------------------------------

/**
 * 回归守卫：服务端把 WebAuthn 列为 provider 但返回空/缺失 challenge
 * （例如 rpId/origin 未配置时的降级响应）。此前前端仍返回 kind='webauthn'，
 * 用户点验证只会反复失败——死胡同。修复后：challenge 为空时不进 webauthn 分支，
 * 让流程落到可用的 TOTP/Email；若 webauthn 是唯一 provider 则返回 kind='error'。
 */
function makeEmptyChallengeResponse(providers: string[]) {
  const providers2: Record<string, unknown> = {
    '7': { challenge: '', allowCredentials: [], rpId: 'example.com', status: 'ok' },
  };
  if (providers.includes('0')) providers2['0'] = null;
  if (providers.includes('1')) providers2['1'] = { Email: 'u***@e***.com' };
  return { TwoFactorProviders: providers, TwoFactorProviders2: providers2, error: 'invalid_grant' };
}

describe('performPasswordLogin – WebAuthn 空 challenge 降级', () => {
  it('providers ["7","0"] 但 challenge 为空 → 落到 totp（不死胡同）', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmptyChallengeResponse(['7', '0']));

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('totp');
  });

  it('providers ["7","1"] 但 challenge 为空 → 落到 email（不死胡同）', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmptyChallengeResponse(['7', '1']));

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('email');
  });

  it('仅 ["7"] 且 challenge 为空 → kind=error（无可用降级因子）', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmptyChallengeResponse(['7']));

    const result = await performPasswordLogin('user@example.com', 'password', 600000);

    expect(result.kind).toBe('error');
  });
});

describe('performUnlock – WebAuthn 空 challenge 降级', () => {
  it('providers ["7","0"] 但 challenge 为空 → 落到 totp', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmptyChallengeResponse(['7', '0']));

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('totp');
  });

  it('仅 ["7"] 且 challenge 为空 → kind=error', async () => {
    (loginWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(makeEmptyChallengeResponse(['7']));

    const result = await performUnlock(MOCK_SESSION, null, 'password', 600000);

    expect(result.kind).toBe('error');
  });
});
