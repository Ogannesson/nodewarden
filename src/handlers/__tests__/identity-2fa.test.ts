/**
 * identity.ts – password grant 2FA 分支回归测试
 *
 * 策略：mock 掉 StorageService / AuthService / RateLimitService / audit 工具，
 * 只测试 handleToken 的 2FA 决策逻辑（挑战响应 / provider 派发 / 恢复码处理 / remember 令牌）。
 *
 * 这些测试锁定**当前行为快照**，作为 P0/P1 重构的安全网。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleToken } from '../identity';
import type { User } from '../../types';

// -----------------------------------------------------------------------
// Mock 所有外部依赖（仅 identity.ts 直接 import 的）
// -----------------------------------------------------------------------

vi.mock('../../services/storage', () => ({
  StorageService: function () { return mockStorage; },
}));

vi.mock('../../services/auth', () => ({
  AuthService: function () { return mockAuth; },
}));

vi.mock('../../services/ratelimit', () => ({
  RateLimitService: function () { return mockRateLimit; },
  getClientIdentifier: vi.fn(() => '127.0.0.1'),
}));

vi.mock('../../utils/jwt', () => ({
  createRefreshToken: vi.fn(() => 'test-refresh-token'),
}));

vi.mock('../../utils/user-decryption', () => ({
  buildAccountKeys: vi.fn(() => ({})),
  buildUserDecryptionOptions: vi.fn(() => ({})),
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
}));

vi.mock('../sends', () => ({
  issueSendAccessToken: vi.fn(() => Promise.resolve({ error: new Response('not found', { status: 404 }) })),
}));

// Registry and provider are thin wrappers — use the real implementations.
// No need to mock two-factor registry; it reads from the real TOTP provider
// which just calls isTotpEnabled(user.totpSecret) and verifyTotpToken().

// -----------------------------------------------------------------------
// Mock 对象（在每个测试前重置）
// -----------------------------------------------------------------------

const mockStorage = {
  getUser: vi.fn(),
  getUserById: vi.fn(),
  saveUser: vi.fn(() => Promise.resolve()),
  getDevice: vi.fn(() => Promise.resolve(null)),
  upsertDevice: vi.fn(() => Promise.resolve()),
  touchDeviceLastSeen: vi.fn(() => Promise.resolve()),
  getTrustedTwoFactorDeviceTokenUserId: vi.fn<() => Promise<string | null>>(() => Promise.resolve(null)),
  saveTrustedTwoFactorDeviceToken: vi.fn(() => Promise.resolve()),
  deleteRefreshTokensByUserId: vi.fn(() => Promise.resolve()),
  deleteRefreshToken: vi.fn(() => Promise.resolve()),
  constrainRefreshTokenExpiry: vi.fn(() => Promise.resolve()),
  // P0/P1: two_factors repo methods
  getTwoFactorsByUserId: vi.fn(() => Promise.resolve([])),
  // P1: called when recovery code disables ALL 2FA providers (account-level escape hatch)
  deleteAllTwoFactorsByUserId: vi.fn(() => Promise.resolve(0)),
  // C4: called after successful login to clean up transient Email OTP challenge rows
  deleteTransientTwoFactorsByUserId: vi.fn(() => Promise.resolve(0)),
  // H5: atomic recovery-code consume (identity.ts login flow) — fail-closed
  atomicConsumeRecoveryCode: vi.fn(() => Promise.resolve(true)),
};

const mockAuth = {
  verifyPassword: vi.fn(() => Promise.resolve(true)),
  generateAccessToken: vi.fn(() => Promise.resolve('test-access-token')),
  generateRefreshToken: vi.fn(() => Promise.resolve('test-refresh-token')),
  refreshAccessTokenDetailed: vi.fn(),
};

const mockRateLimit = {
  checkLoginAttempt: vi.fn(() => Promise.resolve({ allowed: true })),
  recordFailedLogin: vi.fn(() => Promise.resolve({ locked: false })),
  clearLoginAttempts: vi.fn(() => Promise.resolve()),
  consumeBudget: vi.fn(() => Promise.resolve({ allowed: true })),
};

// -----------------------------------------------------------------------
// 测试数据工厂
// -----------------------------------------------------------------------

const FIXED_NOW_MS = 1700000000000; // 2023-11-14

function makeActiveUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-001',
    email: 'test@example.com',
    name: 'Test User',
    masterPasswordHint: null,
    masterPasswordHash: 'hashed-password',
    key: 'user-key',
    privateKey: null,
    publicKey: null,
    kdfType: 0,
    kdfIterations: 600000,
    kdfMemory: undefined,
    kdfParallelism: undefined,
    securityStamp: 'stamp-001',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpEnabled: true,
    totpRecoveryCode: null,
    totpLastCounter: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
    ...overrides,
  };
}

/** 构造 password grant 的 URL-encoded body */
function makePasswordBody(params: Record<string, string>): string {
  const defaults = {
    grant_type: 'password',
    username: 'test@example.com',
    password: 'hashed-password',
    deviceIdentifier: 'device-abc',
    deviceName: 'Test Device',
    deviceType: '0',
  };
  const merged = { ...defaults, ...params };
  return new URLSearchParams(merged).toString();
}

function makeRequest(body: string, headers: Record<string, string> = {}): Request {
  return new Request('https://example.com/identity/connect/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'CF-Connecting-IP': '127.0.0.1',
      ...headers,
    },
    body,
  });
}

/** 最小化 DB mock：支持 TOTP provider 写回 totp_last_counter */
const fakeDb = {
  prepare: (_sql: string) => ({
    bind: (..._args: unknown[]) => ({
      run: () => Promise.resolve({ meta: { changes: 1 } }),
      first: () => Promise.resolve(null),
      all: () => Promise.resolve({ results: [] }),
    }),
  }),
} as unknown as D1Database;

/** 最小化 Env mock */
const fakeEnv = {
  DB: fakeDb,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
  NOTIFICATIONS_HUB: {} as DurableObjectNamespace,
  BACKUP_TRANSFER_RUNNER: {} as DurableObjectNamespace,
};

// -----------------------------------------------------------------------
// 测试 helpers
// -----------------------------------------------------------------------

/** 从 Response 解析 JSON body，返回 null 如果解析失败 */
async function parseBody(resp: Response): Promise<Record<string, unknown>> {
  return resp.json();
}

// -----------------------------------------------------------------------
// 测试套件
// -----------------------------------------------------------------------

describe('handleToken (password grant) – 无 2FA 用户', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('无 TOTP 密钥的用户应直接返回 200 和 access_token', async () => {
    const user = makeActiveUser({ totpSecret: null });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({}));
    const resp = await handleToken(req, fakeEnv as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    const body = await parseBody(resp);
    expect(body.access_token).toBe('test-access-token');
    expect(body.error).toBeUndefined();
  });
});

describe('handleToken (password grant) – 2FA 挑战触发', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockStorage.getDevice.mockResolvedValue(null);
  });

  it('有 TOTP 密钥且未提供 2FA token → 返回 400 挑战响应', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({}));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.error).toBe('invalid_grant');
    expect(body.TwoFactorProviders).toBeDefined();
    expect(body.TwoFactorProviders2).toBeDefined();
    // provider 0 = Authenticator 必须出现
    const providers = body.TwoFactorProviders as string[];
    expect(providers).toContain('0');
  });

  it('有 TOTP 密钥且有恢复码 → 挑战响应同时包含 provider -1（恢复码）', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567',
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({}));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    const providers = body.TwoFactorProviders as string[];
    expect(providers).toContain('0');
    expect(providers).toContain('-1');
  });

  it('提供了 twoFactorProvider 但没有 twoFactorToken → 仍然返回挑战', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({ twoFactorProvider: '0' }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.TwoFactorProviders).toBeDefined();
  });
});

describe('handleToken (password grant) – provider 0 TOTP 验证', () => {
  // 使用固定时间生成已知 TOTP 供测试使用
  const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
  });

  it('正确 TOTP token（provider=0）应通过验证，返回 200', async () => {
    const user = makeActiveUser({ totpSecret: TEST_SECRET });
    mockStorage.getUser.mockResolvedValue(user);

    // 生成当前时刻有效 token
    const validToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '0',
      twoFactorToken: validToken,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    const body = await parseBody(resp);
    expect(body.access_token).toBe('test-access-token');
  });

  it('错误 TOTP token（provider=0）应返回 400 invalid_grant', async () => {
    const user = makeActiveUser({ totpSecret: TEST_SECRET });
    mockStorage.getUser.mockResolvedValue(user);

    // counter=0 对应 Unix epoch（1970-01-01），永远落在当前时间窗口外（window ±1 步长）。
    // 先用 sanity 断言确认它不等于 prev/curr/next，再无条件断言 400。
    const nowCounter = Math.floor(Date.now() / 1000 / 30);
    const epochToken = await computeHotp(TEST_SECRET, 0);
    const prevToken = await computeHotp(TEST_SECRET, nowCounter - 1);
    const currToken = await computeHotp(TEST_SECRET, nowCounter);
    const nextToken = await computeHotp(TEST_SECRET, nowCounter + 1);
    // sanity check: epoch token must not coincidentally match any valid window token
    expect(epochToken).not.toBe(prevToken);
    expect(epochToken).not.toBe(currToken);
    expect(epochToken).not.toBe(nextToken);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '0',
      twoFactorToken: epochToken,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.error).toBe('invalid_grant');
  });
});

describe('handleToken (password grant) – provider 5 remember 令牌', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
  });

  it('有效 remember token（provider=5）应通过，返回 200', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);
    // mock 返回与用户 id 匹配
    mockStorage.getTrustedTwoFactorDeviceTokenUserId.mockResolvedValue(user.id);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '5',
      twoFactorToken: 'valid-remember-token',
      deviceIdentifier: 'device-abc',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
  });

  it('无效 remember token（provider=5）→ 重新进入挑战流程，返回 400', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);
    // mock 返回 null（token 不存在或已过期）
    mockStorage.getTrustedTwoFactorDeviceTokenUserId.mockResolvedValue(null);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '5',
      twoFactorToken: 'expired-remember-token',
      deviceIdentifier: 'device-abc',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    // 应再次发出挑战（TwoFactorProviders 存在），而不是 invalid_grant 错误
    expect(body.TwoFactorProviders).toBeDefined();
  });

  it('remember token 且无 deviceIdentifier → 重新进入挑战', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '5',
      twoFactorToken: 'some-token',
      deviceIdentifier: '',  // 无 deviceIdentifier
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.TwoFactorProviders).toBeDefined();
  });
});

describe('handleToken (password grant) – 恢复码（provider -1 / 8 / 100）', () => {
  const RECOVERY_CODE = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';

  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
    mockStorage.saveUser.mockResolvedValue(undefined);
    mockStorage.deleteRefreshTokensByUserId.mockResolvedValue(undefined);
    mockStorage.deleteAllTwoFactorsByUserId.mockResolvedValue(0);
  });

  it('正确恢复码（provider=-1）应通过验证，禁用 TOTP，返回 200', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '-1',
      twoFactorToken: RECOVERY_CODE,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    // H5 加固：改用原子消费，不再直接 saveUser；验证原子消费被调用
    expect(mockStorage.atomicConsumeRecoveryCode).toHaveBeenCalledWith(user.id, RECOVERY_CODE);
    // 原子消费已在 DB 层清除恢复码，不应再调用 saveUser
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
    // P1 加固：恢复码是账户级逃生门，必须同时清除 two_factors 表所有 provider 行
    expect(mockStorage.deleteAllTwoFactorsByUserId).toHaveBeenCalledWith(user.id);
    // 应撤销现有 refresh tokens
    expect(mockStorage.deleteRefreshTokensByUserId).toHaveBeenCalledWith(user.id);
  });

  it('正确恢复码（legacy provider=8）也应通过', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '8',
      twoFactorToken: RECOVERY_CODE,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
  });

  it('正确恢复码（Android provider=100）也应通过', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '100',
      twoFactorToken: RECOVERY_CODE,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
  });

  it('错误恢复码（provider=-1）应返回 400', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '-1',
      twoFactorToken: 'XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    // 恢复码比对失败后不应发起原子消费（fail-closed：跳过 DB 写操作）
    expect(mockStorage.atomicConsumeRecoveryCode).not.toHaveBeenCalled();
  });

  it('恢复码竞争消费（atomicConsumeRecoveryCode 返回 false）应返回 400 且不清除 two_factors/refresh tokens', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);
    // 模拟 D1 WHERE predicate 匹配不到行（并发消费/changes===0）
    mockStorage.atomicConsumeRecoveryCode.mockResolvedValueOnce(false);
    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '-1',
      twoFactorToken: RECOVERY_CODE,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });
    expect(resp.status).toBe(400);
    // fail-closed：原子消费失败后不得继续清除 two_factors 或撤销 refresh tokens
    expect(mockStorage.deleteAllTwoFactorsByUserId).not.toHaveBeenCalled();
    expect(mockStorage.deleteRefreshTokensByUserId).not.toHaveBeenCalled();
  });

  it('恢复码通过后不应颁发新的 remember token（twoFactorRemember=1 被忽略）', async () => {
    const user = makeActiveUser({
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpRecoveryCode: RECOVERY_CODE,
    });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '-1',
      twoFactorToken: RECOVERY_CODE,
      twoFactorRemember: '1',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    const body = await parseBody(resp);
    // 恢复码后不应有 TwoFactorToken（remember token）
    expect(body.TwoFactorToken).toBeUndefined();
    expect(mockStorage.saveTrustedTwoFactorDeviceToken).not.toHaveBeenCalled();
  });
});

describe('handleToken (password grant) – 未知 provider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockStorage.getDevice.mockResolvedValue(null);
  });

  it('未知 provider（如 99）应被拒绝，返回 400', async () => {
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '99',
      twoFactorToken: '123456',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.error).toBe('invalid_grant');
    // 必修加固 #1：未知 provider 失败必须计入失败限速，防止枚举
    expect(mockRateLimit.recordFailedLogin).toHaveBeenCalled();
  });
});

describe('handleToken (password grant) – provider=7 防绕过（安全护栏）', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockStorage.getDevice.mockResolvedValue(null);
  });

  it('TOTP 用户（无 WebAuthn 凭据）提交 provider=7 必须被拒，返回 400 invalid_grant 并计入限速', async () => {
    // 启用了 TOTP 但没有注册任何 WebAuthn 凭据的用户
    const user = makeActiveUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    mockStorage.getUser.mockResolvedValue(user);
    // getTwoFactorsByUserId 返回空数组 → WebAuthnProvider.isEnabledForUser = false
    mockStorage.getTwoFactorsByUserId.mockResolvedValue([]);

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '7',
      twoFactorToken: 'fake-webauthn-assertion',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    // WebAuthn 未对该用户启用 → 已知但未注册的 provider → 拒绝，防止绕过 TOTP
    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.error).toBe('invalid_grant');
    // 失败必须计入限速（recordFailedTwoFactor → recordFailedLogin），防止暴力枚举
    expect(mockRateLimit.recordFailedLogin).toHaveBeenCalled();
  });
});

describe('handleToken (password grant) – remember token 颁发', () => {
  const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
    mockStorage.saveTrustedTwoFactorDeviceToken.mockResolvedValue(undefined);
  });

  it('正确 TOTP + twoFactorRemember=1 + 有 deviceIdentifier → 颁发 TwoFactorToken', async () => {
    const user = makeActiveUser({ totpSecret: TEST_SECRET });
    mockStorage.getUser.mockResolvedValue(user);

    const validToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '0',
      twoFactorToken: validToken,
      twoFactorRemember: '1',
      deviceIdentifier: 'device-abc',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    const body = await parseBody(resp);
    expect(body.TwoFactorToken).toBeDefined();
    expect(mockStorage.saveTrustedTwoFactorDeviceToken).toHaveBeenCalled();
  });

  it('正确 TOTP + twoFactorRemember=0 → 不颁发 TwoFactorToken', async () => {
    const user = makeActiveUser({ totpSecret: TEST_SECRET });
    mockStorage.getUser.mockResolvedValue(user);

    const validToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '0',
      twoFactorToken: validToken,
      twoFactorRemember: '0',
      deviceIdentifier: 'device-abc',
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    const body = await parseBody(resp);
    expect(body.TwoFactorToken).toBeUndefined();
  });
});

// -----------------------------------------------------------------------
// H2: Email buildChallenge 失败韧性测试
// -----------------------------------------------------------------------

describe('handleToken (password grant) – H2: buildChallenge 韧性', () => {
  const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
    mockStorage.deleteTransientTwoFactorsByUserId.mockResolvedValue(0);
  });

  it('Email buildChallenge 抛异常时，TOTP 用户仍拿到正常 400 挑战响应', async () => {
    // 用户同时启用了 TOTP 和 Email 2FA
    const user = makeActiveUser({
      totpSecret: TEST_SECRET,
      totpRecoveryCode: 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567',
    });
    mockStorage.getUser.mockResolvedValue(user);

    // Email provider 的 two_factors 行：atype=1, enabled=true
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mockStorage.getTwoFactorsByUserId as any).mockResolvedValue([
      {
        userId: user.id,
        atype: 1, // Email enrollment
        enabled: true,
        data: JSON.stringify({ email: 'test@example.com' }),
        lastUsed: null,
        createdAt: '2023-01-01T00:00:00Z',
        updatedAt: '2023-01-01T00:00:00Z',
      },
    ]);

    // 注意：Email provider 的 buildChallenge 会调用 email sender；
    // fakeEnv 没有配置 email 后端，所以 buildChallenge 会抛异常
    // → 期望：TOTP provider 的挑战仍然正常返回，整体返回 400（不是 500）

    const req = makeRequest(makePasswordBody({}));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    // 必须是 400（2FA 挑战），而不是 500（未捕获异常）
    expect(resp.status).toBe(400);
    const body = await parseBody(resp);
    expect(body.error).toBe('invalid_grant');
    // TOTP（provider 0）仍必须出现在挑战列表中
    const providers = body.TwoFactorProviders as string[];
    expect(providers).toContain('0');
    // 恢复码 (-1) 也应出现（用户有 totpRecoveryCode）
    expect(providers).toContain('-1');
  });
});

// -----------------------------------------------------------------------
// C4: 成功登录后清理 transient challenge 行测试
// -----------------------------------------------------------------------

describe('handleToken (password grant) – C4: transient challenge 清理', () => {
  const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    vi.clearAllMocks();
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue({ locked: false });
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockAuth.generateAccessToken.mockResolvedValue('test-access-token');
    mockAuth.generateRefreshToken.mockResolvedValue('test-refresh-token');
    mockStorage.getDevice.mockResolvedValue(null);
    mockStorage.deleteTransientTwoFactorsByUserId.mockResolvedValue(0);
  });

  it('TOTP 登录成功后应调用 deleteTransientTwoFactorsByUserId 清理 Email OTP 行', async () => {
    const user = makeActiveUser({ totpSecret: TEST_SECRET });
    mockStorage.getUser.mockResolvedValue(user);

    const validToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));

    const req = makeRequest(makePasswordBody({
      twoFactorProvider: '0',
      twoFactorToken: validToken,
    }));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    // C4: 成功登录后必须清理 transient 行
    expect(mockStorage.deleteTransientTwoFactorsByUserId).toHaveBeenCalledWith(user.id);
  });

  it('无 2FA 用户登录成功后也应清理 transient challenge 行（防残留）', async () => {
    const user = makeActiveUser({ totpSecret: null });
    mockStorage.getUser.mockResolvedValue(user);

    const req = makeRequest(makePasswordBody({}));
    const resp = await handleToken(req, fakeEnv as unknown as typeof fakeEnv & { DB: D1Database });

    expect(resp.status).toBe(200);
    // 即使没有 2FA，也应调用清理（用户可能之前有过 Email challenge 残留）
    expect(mockStorage.deleteTransientTwoFactorsByUserId).toHaveBeenCalledWith(user.id);
  });
});

// -----------------------------------------------------------------------
// 辅助函数（与 totp.ts 相同算法，用于生成期望值）
// -----------------------------------------------------------------------

function base32Decode(input: string): Uint8Array | null {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = input.toUpperCase().replace(/[\s\-=]/g, '');
  if (!normalized) return null;

  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >> bits) & 0xff);
    }
  }

  return output.length > 0 ? new Uint8Array(output) : null;
}

async function computeHotp(secretBase32: string, counter: number): Promise<string> {
  const secret = base32Decode(secretBase32)!;
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return (binary % 1_000_000).toString().padStart(6, '0');
}
