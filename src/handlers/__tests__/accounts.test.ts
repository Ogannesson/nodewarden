/**
 * accounts.test.ts — handleRecoverTwoFactor TOCTOU 防竞态测试
 *
 * 验证：当 atomicRotateRecoveryCode 返回 false（条件 UPDATE changes===0，
 * 表示并发请求已抢先完成），处理器必须 fail-closed：
 *   - 返回 HTTP 400
 *   - 记录失败登录限流
 *   - 不调用 deleteAllTwoFactorsByUserId
 *   - 不调用 deleteRefreshTokensByUserId
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleRecoverTwoFactor } from '../accounts';

// -----------------------------------------------------------------------
// Mock 声明（必须在顶层，vi.mock 会被 hoisted）
// -----------------------------------------------------------------------

const mockStorage = {
  getUser: vi.fn(),
  atomicRotateRecoveryCode: vi.fn(() => Promise.resolve(true)),
  deleteAllTwoFactorsByUserId: vi.fn(() => Promise.resolve(0)),
  deleteRefreshTokensByUserId: vi.fn(() => Promise.resolve()),
};

const mockAuth = {
  verifyPassword: vi.fn(() => Promise.resolve(true)),
};

const mockRateLimit = {
  checkLoginAttempt: vi.fn(() => Promise.resolve({ allowed: true })),
  recordFailedLogin: vi.fn(() => Promise.resolve()),
  clearLoginAttempts: vi.fn(() => Promise.resolve()),
};

vi.mock('../../services/storage', () => ({
  StorageService: function () {
    return mockStorage;
  },
}));

vi.mock('../../services/auth', () => {
  const MockAuthService = function () {
    return mockAuth;
  } as any;
  MockAuthService.invalidateUserCache = vi.fn();
  return { AuthService: MockAuthService };
});

vi.mock('../../services/ratelimit', () => ({
  RateLimitService: function () {
    return mockRateLimit;
  },
  getClientIdentifier: vi.fn(() => '127.0.0.1'),
}));

vi.mock('../../utils/recovery-code', () => ({
  recoveryCodeEquals: vi.fn(() => Promise.resolve({ match: true })),
  createRecoveryCode: vi.fn(() => 'new-plain-code'),
  hashRecoveryCode: vi.fn(() => Promise.resolve('new-hashed-code')),
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
  writeAuditEvent: vi.fn(() => Promise.resolve()),
}));

vi.mock('../../utils/uuid', () => ({
  generateUUID: vi.fn(() => 'test-uuid'),
}));

// -----------------------------------------------------------------------
// 测试辅助
// -----------------------------------------------------------------------

/** 构造一个已启用 2FA 的用户对象 */
function makeUser(overrides: Record<string, unknown> = {}) {
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
    totpSecret: 'secret-base32',
    totpEnabled: true,
    totpRecoveryCode: 'hashed-recovery-code',
    totpLastCounter: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
    ...overrides,
  };
}

/** 构造 handleRecoverTwoFactor 的 POST JSON 请求 */
function makeRecoverRequest(
  body: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request('https://example.com/api/two-factor/recover', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'CF-Connecting-IP': '127.0.0.1',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

/** 最小化 Env mock */
const fakeEnv = {
  DB: {} as D1Database,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
  NOTIFICATIONS_HUB: {} as DurableObjectNamespace,
  BACKUP_TRANSFER_RUNNER: {} as DurableObjectNamespace,
};

// -----------------------------------------------------------------------
// 测试套件
// -----------------------------------------------------------------------

describe('handleRecoverTwoFactor — atomicRotateRecoveryCode TOCTOU 防竞态', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // 默认恢复：大多数测试使用 "正常路径" 的 mock 值
    mockRateLimit.checkLoginAttempt.mockResolvedValue({ allowed: true });
    mockRateLimit.recordFailedLogin.mockResolvedValue(undefined);
    mockRateLimit.clearLoginAttempts.mockResolvedValue(undefined);
    mockStorage.getUser.mockResolvedValue(makeUser());
    mockStorage.atomicRotateRecoveryCode.mockResolvedValue(true);
    mockStorage.deleteAllTwoFactorsByUserId.mockResolvedValue(0);
    mockStorage.deleteRefreshTokensByUserId.mockResolvedValue(undefined);
    mockAuth.verifyPassword.mockResolvedValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('当 atomicRotateRecoveryCode 返回 false（并发竞态），应 fail-closed：返回 400，记录限流，不执行后续销毁', async () => {
    // 模拟并发场景：另一个请求已抢先原子消费了恢复码（WHERE predicate 不匹配，changes===0）
    mockStorage.atomicRotateRecoveryCode.mockResolvedValueOnce(false);

    const req = makeRecoverRequest({
      email: 'test@example.com',
      masterPasswordHash: 'hash',
      recoveryCode: 'ABCD1234',
    });

    const resp = await handleRecoverTwoFactor(req, fakeEnv as any);

    // 应返回 400
    expect(resp.status).toBe(400);

    // 应记录失败登录以触发限流计数
    expect(mockRateLimit.recordFailedLogin).toHaveBeenCalledWith('127.0.0.1:recover-2fa');

    // 绝对不能执行后续的账户销毁操作（fail-closed）
    expect(mockStorage.deleteAllTwoFactorsByUserId).not.toHaveBeenCalled();
    expect(mockStorage.deleteRefreshTokensByUserId).not.toHaveBeenCalled();
  });
});
