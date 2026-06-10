/**
 * totp-replay-claim.test.ts
 *
 * Regression for the TOTP setup / re-enable replay window:
 *
 * Both handleSetTotpStatus paths that accept a live 6-digit code — initial
 * `{ enabled:true, secret, token }` setup and `{ enabled:true, masterPasswordHash, token }`
 * re-enable — previously verified the code WITHOUT advancing users.totp_last_counter.
 * That left the just-verified code replayable against the login endpoint within its
 * ~90-second validity window. The fix claims the matched counter via
 * storage.updateTotpLastCounter(); a failed claim (counter already consumed / concurrent
 * race) is treated as a verification failure.
 *
 * Invariants verified per path:
 *   1. Success → updateTotpLastCounter(userId, matchedCounter) is called and the user is saved enabled.
 *   2. Counter claim returns false → HTTP 400, user NOT saved (no enable side effects).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks (hoisted)
// ---------------------------------------------------------------------------

const mockStorage = {
  getUserById: vi.fn(),
  saveUser: vi.fn<(user: Record<string, unknown>) => Promise<void>>(() => Promise.resolve()),
  deleteRefreshTokensByUserId: vi.fn(() => Promise.resolve()),
  updateTotpLastCounter: vi.fn<(userId: string, counter: number) => Promise<boolean>>(() => Promise.resolve(true)),
};

const mockAuth = {
  verifyPassword: vi.fn(() => Promise.resolve(true)),
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
    return { consumeBudgetWithWindow: vi.fn(() => Promise.resolve({ allowed: true })) };
  },
  getClientIdentifier: vi.fn(() => '127.0.0.1'),
}));

// verifyTotpToken returns the matched counter (number) or null. isTotpEnabled gates
// the re-enable/secret checks. normalizeTotpSecret is a private fn in accounts.ts and
// is intentionally left running against the real (un-mocked) base32 secret.
const mockVerifyTotpToken = vi.fn<(...a: unknown[]) => Promise<number | null>>(() => Promise.resolve(42));
vi.mock('../../utils/totp', () => ({
  verifyTotpToken: (...args: unknown[]) => mockVerifyTotpToken(...args),
  isTotpEnabled: vi.fn((s: string | null | undefined) => !!(s && s.length > 0)),
}));

vi.mock('../../utils/recovery-code', () => ({
  createRecoveryCode: vi.fn(() => 'plain-recovery'),
  hashRecoveryCode: vi.fn(() => Promise.resolve('hashed-recovery')),
  recoveryCodeEquals: vi.fn(() => Promise.resolve({ match: true })),
  sha256Hex: vi.fn(() => Promise.resolve('hash')),
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
  writeAuditEvent: vi.fn(() => Promise.resolve()),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { handleSetTotpStatus } from '../accounts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// A real, normalizable base32 secret so the un-mocked normalizeTotpSecret passes.
const VALID_SECRET = 'JBSWY3DPEHPK3PXP';

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

function makeRequest(body: Record<string, unknown>): Request {
  return new Request('https://example.com/api/accounts/totp', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '127.0.0.1' },
    body: JSON.stringify(body),
  });
}

const fakeEnv = {
  DB: {} as D1Database,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
} as unknown as import('../../types').Env;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('handleSetTotpStatus — TOTP setup path replay protection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStorage.updateTotpLastCounter.mockResolvedValue(true);
    mockStorage.saveUser.mockResolvedValue(undefined);
    mockStorage.deleteRefreshTokensByUserId.mockResolvedValue(undefined);
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockVerifyTotpToken.mockResolvedValue(42);
  });

  it('claims the matched counter and enables TOTP on a valid setup code', async () => {
    mockStorage.getUserById.mockResolvedValue(makeUser());

    const resp = await handleSetTotpStatus(
      makeRequest({ enabled: true, secret: VALID_SECRET, token: '123456' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    expect(mockStorage.updateTotpLastCounter).toHaveBeenCalledWith('user-001', 42);
    // Saved user is the enabled one.
    expect(mockStorage.saveUser).toHaveBeenCalledOnce();
    const saved = mockStorage.saveUser.mock.calls[0][0] as { totpEnabled: boolean; totpSecret: string };
    expect(saved.totpEnabled).toBe(true);
    expect(saved.totpSecret).toBe(VALID_SECRET);
  });

  it('rejects with 400 and does NOT enable when the counter claim fails (replay/race)', async () => {
    mockStorage.getUserById.mockResolvedValue(makeUser());
    // Verification matched, but the counter was already consumed (or lost a concurrent race).
    mockStorage.updateTotpLastCounter.mockResolvedValueOnce(false);

    const resp = await handleSetTotpStatus(
      makeRequest({ enabled: true, secret: VALID_SECRET, token: '123456' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(400);
    expect(mockStorage.updateTotpLastCounter).toHaveBeenCalledWith('user-001', 42);
    // Fail closed: no enable side effects.
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
  });

  it('rejects with 400 when the code itself is invalid (no counter claim attempted)', async () => {
    mockStorage.getUserById.mockResolvedValue(makeUser());
    mockVerifyTotpToken.mockResolvedValueOnce(null);

    const resp = await handleSetTotpStatus(
      makeRequest({ enabled: true, secret: VALID_SECRET, token: '000000' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(400);
    expect(mockStorage.updateTotpLastCounter).not.toHaveBeenCalled();
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
  });
});

describe('handleSetTotpStatus — TOTP re-enable path replay protection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStorage.updateTotpLastCounter.mockResolvedValue(true);
    mockStorage.saveUser.mockResolvedValue(undefined);
    mockStorage.deleteRefreshTokensByUserId.mockResolvedValue(undefined);
    mockAuth.verifyPassword.mockResolvedValue(true);
    mockVerifyTotpToken.mockResolvedValue(99);
  });

  it('claims the matched counter and re-enables TOTP on a valid live code', async () => {
    // Re-enable path: secret already stored, disabled flag, master password + live token.
    mockStorage.getUserById.mockResolvedValue(makeUser({ totpSecret: VALID_SECRET, totpEnabled: false }));

    const resp = await handleSetTotpStatus(
      makeRequest({ enabled: true, masterPasswordHash: 'pw-hash', token: '123456' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    expect(mockStorage.updateTotpLastCounter).toHaveBeenCalledWith('user-001', 99);
    expect(mockStorage.saveUser).toHaveBeenCalledOnce();
    const saved = mockStorage.saveUser.mock.calls[0][0] as { totpEnabled: boolean };
    expect(saved.totpEnabled).toBe(true);
  });

  it('rejects with 400 and does NOT re-enable when the counter claim fails (replay/race)', async () => {
    mockStorage.getUserById.mockResolvedValue(makeUser({ totpSecret: VALID_SECRET, totpEnabled: false }));
    mockStorage.updateTotpLastCounter.mockResolvedValueOnce(false);

    const resp = await handleSetTotpStatus(
      makeRequest({ enabled: true, masterPasswordHash: 'pw-hash', token: '123456' }),
      fakeEnv,
      'user-001'
    );

    expect(resp.status).toBe(400);
    expect(mockStorage.updateTotpLastCounter).toHaveBeenCalledWith('user-001', 99);
    expect(mockStorage.saveUser).not.toHaveBeenCalled();
  });
});
