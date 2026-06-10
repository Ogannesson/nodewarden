/**
 * get-totp-recovery-code.test.ts — handleGetTotpRecoveryCode 行为回归
 *
 * 修复前的 bug：启用 TOTP 后恢复码直接以 hash 入库，"查看恢复代码"端点对已存 hash 的
 * 账号返回空 code，用户永远拿不到明文 → 丢失 TOTP 设备即被锁死。
 *
 * 修复后语义（主密码已验证为前提）：
 *   - 已存 hash（非 legacy）：重新生成新明文、入库新 hash、返回新明文，旧 hash 作废。
 *   - 首次生成（无 totpRecoveryCode）：生成并入库 hash、返回明文（行为不变）。
 *   - legacy 明文行：原样返回、不轮换（行为不变）。
 *   - 主密码错误：400，库中 hash 不被改动（不轮换）。
 *
 * 注意：本套件不 mock recovery-code 工具（使用真实 createRecoveryCode/hashRecoveryCode），
 * 以便对返回明文做 base32 格式断言、并验证新旧 hash 不同。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleGetTotpRecoveryCode } from '../accounts';
import { hashRecoveryCode } from '../../utils/recovery-code';

// -----------------------------------------------------------------------
// Mock 声明（顶层，vi.mock 会被 hoisted）；不 mock recovery-code 工具
// -----------------------------------------------------------------------

const mockStorage = {
  getUserById: vi.fn(),
  saveUser: vi.fn(() => Promise.resolve()),
};

const mockAuth = {
  verifyPassword: vi.fn(() => Promise.resolve(true)),
};

const mockRateLimit = {
  consumeBudgetWithWindow: vi.fn(() => Promise.resolve({ allowed: true })),
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

/** 构造一个已启用 TOTP 的用户对象 */
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
    // 64 位小写 hex = 已存 hash（非 legacy）
    totpRecoveryCode: 'a'.repeat(64),
    totpLastCounter: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeRequest(body: Record<string, string>): Request {
  return new Request('https://example.com/api/accounts/totp/recovery-code', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const fakeEnv = {
  DB: {} as D1Database,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
} as any;

// 32 位 base32 明文（含分组空格）格式：4 字符一组、5 组共 32 个 base32 字符。
const BASE32_PLAINTEXT = /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/;

// -----------------------------------------------------------------------
// 测试套件
// -----------------------------------------------------------------------

describe('handleGetTotpRecoveryCode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockRateLimit.consumeBudgetWithWindow.mockResolvedValue({ allowed: true });
    mockStorage.saveUser.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('已存 hash + 主密码正确 → 返回 32 字符 base32 明文，库中 hash 轮换为新码的 hash 且与旧 hash 不同', async () => {
    const oldHash = 'a'.repeat(64);
    const user = makeUser({ totpRecoveryCode: oldHash });
    mockStorage.getUserById.mockResolvedValue(user);

    const resp = await handleGetTotpRecoveryCode(
      makeRequest({ masterPasswordHash: 'hash' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    const json = (await resp.json()) as { code: string; object: string };

    // 返回明文为 32 字符 base32（去掉分组空格后 32 个 base32 字符）
    expect(json.object).toBe('twoFactorRecover');
    expect(json.code).toMatch(BASE32_PLAINTEXT);
    expect(json.code.replace(/ /g, '')).toHaveLength(32);

    // 库被写入；写入的是新明文的 hash，且与旧 hash 不同
    expect(mockStorage.saveUser).toHaveBeenCalledTimes(1);
    const saved = (mockStorage.saveUser.mock.calls[0] as unknown as [{ totpRecoveryCode: string }])[0];
    const expectedHash = await hashRecoveryCode(json.code);
    expect(saved.totpRecoveryCode).toBe(expectedHash);
    expect(saved.totpRecoveryCode).not.toBe(oldHash);
  });

  it('主密码错误 → 400，hash 未被改动（不轮换）', async () => {
    mockAuth.verifyPassword.mockResolvedValue(false);
    const user = makeUser({ totpRecoveryCode: 'a'.repeat(64) });
    mockStorage.getUserById.mockResolvedValue(user);

    const resp = await handleGetTotpRecoveryCode(
      makeRequest({ masterPasswordHash: 'wrong' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(400);
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
    // 不消费轮换预算
    expect(mockRateLimit.consumeBudgetWithWindow).not.toHaveBeenCalled();
  });

  it('legacy 明文行 → 原样返回、不轮换', async () => {
    const legacy = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';
    const user = makeUser({ totpRecoveryCode: legacy });
    mockStorage.getUserById.mockResolvedValue(user);

    const resp = await handleGetTotpRecoveryCode(
      makeRequest({ masterPasswordHash: 'hash' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    const json = (await resp.json()) as { code: string; object: string };
    expect(json.code).toBe(legacy);
    // 不写库、不轮换、不消费预算
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
    expect(mockRateLimit.consumeBudgetWithWindow).not.toHaveBeenCalled();
  });

  it('首次生成路径（无 totpRecoveryCode）→ 生成明文、入库 hash、返回 32 字符 base32（行为不回归）', async () => {
    const user = makeUser({ totpRecoveryCode: null });
    mockStorage.getUserById.mockResolvedValue(user);

    const resp = await handleGetTotpRecoveryCode(
      makeRequest({ masterPasswordHash: 'hash' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    const json = (await resp.json()) as { code: string; object: string };
    expect(json.object).toBe('twoFactorRecover');
    expect(json.code).toMatch(BASE32_PLAINTEXT);

    expect(mockStorage.saveUser).toHaveBeenCalledTimes(1);
    const saved = (mockStorage.saveUser.mock.calls[0] as unknown as [{ totpRecoveryCode: string }])[0];
    expect(saved.totpRecoveryCode).toBe(await hashRecoveryCode(json.code));
    // 首次生成不走轮换预算分支
    expect(mockRateLimit.consumeBudgetWithWindow).not.toHaveBeenCalled();
  });

  it('已存 hash + 轮换预算耗尽 → 429，不写库', async () => {
    mockRateLimit.consumeBudgetWithWindow.mockResolvedValue({ allowed: false });
    const user = makeUser({ totpRecoveryCode: 'a'.repeat(64) });
    mockStorage.getUserById.mockResolvedValue(user);

    const resp = await handleGetTotpRecoveryCode(
      makeRequest({ masterPasswordHash: 'hash' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(429);
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
  });
});
