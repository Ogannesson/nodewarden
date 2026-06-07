/**
 * email-2fa.test.ts
 *
 * 单测覆盖：
 *  1. EmailTwoFactorProvider.isAvailable — HTTP backend / CF-only / 无配置
 *  2. EmailTwoFactorProvider.isEnabledForUser — 有/无 atype=1 enrollment
 *  3. EmailTwoFactorProvider.buildChallenge — 生成并存储 code、调用 sender、返回 masked email
 *  4. EmailTwoFactorProvider.verify — 正确码、错误码、TTL 过期、超出最大尝试次数
 *  5. handleSendEmailLogin — 未配置返回 200、用户不存在返回 200、密码错误返回 200、成功发码
 *  6. maskEmail helper
 *  7. generateNumericCode — 6 位数字
 *  8. handleGetEmailTwoFactor — available 标志反映服务端配置
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { User } from '../../types';
import type { TwoFactorRow } from '../../services/storage-two-factor-repo';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof fetch>();

vi.stubGlobal('fetch', mockFetch);

// Mock storage-two-factor-repo so we control D1 interactions.
const mockGetTwoFactor = vi.fn<() => Promise<TwoFactorRow | null>>(() => Promise.resolve(null));
const mockUpsertTwoFactor = vi.fn(() => Promise.resolve());
const mockDeleteTwoFactor = vi.fn(() => Promise.resolve(true));
const mockGetTwoFactorsByUserId = vi.fn<() => Promise<TwoFactorRow[]>>(() => Promise.resolve([]));

vi.mock('../../services/storage-two-factor-repo', () => ({
  getTwoFactor: vi.fn((...args) => mockGetTwoFactor(...(args as Parameters<typeof mockGetTwoFactor>))),
  upsertTwoFactor: vi.fn((...args) => mockUpsertTwoFactor(...(args as Parameters<typeof mockUpsertTwoFactor>))),
  deleteTwoFactor: vi.fn((...args) => mockDeleteTwoFactor(...(args as Parameters<typeof mockDeleteTwoFactor>))),
  getTwoFactorsByUserId: vi.fn((...args) => mockGetTwoFactorsByUserId(...(args as Parameters<typeof mockGetTwoFactorsByUserId>))),
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
  writeAuditEvent: vi.fn(() => Promise.resolve()),
}));

// Mock StorageService used by handleSendEmailLogin and handleGetEmailTwoFactor.
const mockStorageGetUser = vi.fn<() => Promise<User | null>>();
const mockStorageGetUserById = vi.fn<() => Promise<User | null>>();
const mockStorageSaveUser = vi.fn(() => Promise.resolve());
vi.mock('../../services/storage', () => ({
  StorageService: function () {
    return {
      getUser: mockStorageGetUser,
      getUserById: mockStorageGetUserById,
      saveUser: mockStorageSaveUser,
    };
  },
}));

const mockAuthVerify = vi.fn<() => Promise<boolean>>(() => Promise.resolve(true));
vi.mock('../../services/auth', () => ({
  AuthService: function () {
    return { verifyPassword: mockAuthVerify };
  },
}));

const mockCheckLoginAttempt = vi.fn(() => Promise.resolve({ allowed: true }));
const mockRecordFailedLogin = vi.fn(() => Promise.resolve({ locked: false }));
const mockConsumeBudgetWithWindow = vi.fn(() => Promise.resolve({ allowed: true, remaining: 4 }));
vi.mock('../../services/ratelimit', () => ({
  RateLimitService: function () {
    return {
      checkLoginAttempt: mockCheckLoginAttempt,
      recordFailedLogin: mockRecordFailedLogin,
      consumeBudgetWithWindow: mockConsumeBudgetWithWindow,
    };
  },
  getClientIdentifier: vi.fn(() => '127.0.0.1'),
}));

vi.mock('../../utils/user-decryption', () => ({
  buildAccountKeys: vi.fn(() => ({})),
  buildUserDecryptionOptions: vi.fn(() => ({})),
}));

vi.mock('../../utils/jwt', () => ({
  createRefreshToken: vi.fn(() => 'test-refresh-token'),
}));

vi.mock('../sends', () => ({
  issueSendAccessToken: vi.fn(() => Promise.resolve({ error: new Response('not found', { status: 404 }) })),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks are registered)
// ---------------------------------------------------------------------------

import {
  emailProvider,
  EMAIL_ENROLLMENT_ATYPE,
  EMAIL_LOGIN_CHALLENGE_ATYPE,
  generateNumericCode,
  maskEmail,
  CODE_TTL_S,
  MAX_ATTEMPTS,
} from '../../services/two-factor/email-provider';
import { handleSendEmailLogin } from '../identity';
import { handleGetEmailTwoFactor } from '../accounts';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeUser(overrides: Partial<User> = {}): User {
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

function makeEnrollmentRow(email = 'test@example.com'): TwoFactorRow {
  return {
    userId: 'user-001',
    atype: EMAIL_ENROLLMENT_ATYPE,
    enabled: true,
    data: JSON.stringify({ email }),
    lastUsed: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
  };
}

function makeChallengeRow(overrides: Partial<{ code: string; createdAt: number; attempts: number }> = {}): TwoFactorRow {
  return {
    userId: 'user-001',
    atype: EMAIL_LOGIN_CHALLENGE_ATYPE,
    enabled: true,
    data: JSON.stringify({ code: '123456', createdAt: Date.now(), attempts: 0, ...overrides }),
    lastUsed: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
  };
}

// Env configured with generic HTTP backend (drives all existing send-path tests).
const fakeEnv = {
  DB: {} as D1Database,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
  NOTIFICATIONS_HUB: {} as DurableObjectNamespace,
  MFA_EMAIL_HTTP_ENDPOINT: 'http://localhost:9876/send',
  MFA_EMAIL_HTTP_AUTH: 'Bearer test-token',
  MFA_EMAIL_FROM: 'noreply@example.com',
};

const fakeEnvNoEmail = {
  DB: {} as D1Database,
  JWT_SECRET: 'test-secret-at-least-32-characters-long',
  NOTIFICATIONS_HUB: {} as DurableObjectNamespace,
  // No MFA_EMAIL_FROM / no backend configured
};

// ---------------------------------------------------------------------------
// 1. EmailTwoFactorProvider — isAvailable
// ---------------------------------------------------------------------------

describe('emailProvider.isAvailable', () => {
  it('returns false when no email backend is configured', () => {
    expect(emailProvider.isAvailable(fakeEnvNoEmail as typeof fakeEnv)).toBe(false);
  });

  it('returns false when only MFA_EMAIL_FROM is set (no backend)', () => {
    expect(emailProvider.isAvailable({ ...fakeEnvNoEmail, MFA_EMAIL_FROM: 'noreply@example.com' } as typeof fakeEnv)).toBe(false);
  });

  it('returns true when generic HTTP backend + MFA_EMAIL_FROM are set', () => {
    expect(emailProvider.isAvailable(fakeEnv as typeof fakeEnv)).toBe(true);
  });

  it('returns true when Cloudflare EMAIL binding + MFA_EMAIL_FROM are set (CF-only deployment)', () => {
    const cfEnv = {
      ...fakeEnvNoEmail,
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: { send: vi.fn().mockResolvedValue({ messageId: 'cf-msg-001' }) },
    };
    expect(emailProvider.isAvailable(cfEnv as unknown as typeof fakeEnv)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 2. EmailTwoFactorProvider — isEnabledForUser
// ---------------------------------------------------------------------------

describe('emailProvider.isEnabledForUser', () => {
  const user = makeUser();

  it('returns false when no two_factors rows', () => {
    expect(emailProvider.isEnabledForUser(user, [])).toBe(false);
  });

  it('returns false when enrollment row is disabled', () => {
    const rows: TwoFactorRow[] = [{ ...makeEnrollmentRow(), enabled: false }];
    expect(emailProvider.isEnabledForUser(user, rows)).toBe(false);
  });

  it('returns true when enabled atype=1 row exists', () => {
    expect(emailProvider.isEnabledForUser(user, [makeEnrollmentRow()])).toBe(true);
  });

  it('ignores rows with other atypes', () => {
    const rows: TwoFactorRow[] = [{ ...makeEnrollmentRow(), atype: 7 }]; // WebAuthn atype
    expect(emailProvider.isEnabledForUser(user, rows)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 3. EmailTwoFactorProvider — buildChallenge
// ---------------------------------------------------------------------------

describe('emailProvider.buildChallenge', () => {
  beforeEach(() => vi.clearAllMocks());

  it('throws when no enrollment row', async () => {
    const ctx = {
      user: makeUser(),
      env: fakeEnv as typeof fakeEnv,
      db: {} as D1Database,
      twoFactorRows: [],
    };
    await expect(emailProvider.buildChallenge(ctx)).rejects.toThrow('Email 2FA not enrolled');
  });

  it('returns masked email only — does NOT generate, store, or send a code', async () => {
    // Regression guard: sending is owned solely by handleSendEmailLogin. buildChallenge
    // only announces the masked destination for TwoFactorProviders2["1"]. Previously it
    // also generated + sent a code, causing two emails per login (the first immediately
    // overwritten/invalidated by the client-triggered send).
    const ctx = {
      user: makeUser(),
      env: fakeEnv as typeof fakeEnv,
      db: {} as D1Database,
      twoFactorRows: [makeEnrollmentRow('user@example.com')],
    };
    const result = await emailProvider.buildChallenge(ctx) as { Email: string };
    expect(result.Email).toMatch(/^u\*\*\*@/);            // masked, capital-E key
    expect(mockUpsertTwoFactor).not.toHaveBeenCalled();   // no challenge row written
    expect(mockFetch).not.toHaveBeenCalled();             // no email sent
  });

  it('does not touch the sender even when email backend is unconfigured', async () => {
    // buildChallenge must announce the provider regardless of sender config — an
    // unconfigured backend must not block the challenge list (it only blocks send,
    // which is handleSendEmailLogin's job).
    const ctx = {
      user: makeUser(),
      env: fakeEnvNoEmail as typeof fakeEnv,
      db: {} as D1Database,
      twoFactorRows: [makeEnrollmentRow('user@example.com')],
    };
    const result = await emailProvider.buildChallenge(ctx) as { Email: string };
    expect(result.Email).toMatch(/^u\*\*\*@/);
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// 4. EmailTwoFactorProvider — verify
// ---------------------------------------------------------------------------

describe('emailProvider.verify', () => {
  beforeEach(() => vi.clearAllMocks());

  const baseCtx = {
    user: makeUser(),
    env: fakeEnv as typeof fakeEnv,
    db: {} as D1Database,
    twoFactorRows: [makeEnrollmentRow()],
  };

  it('returns false when no challenge row exists', async () => {
    mockGetTwoFactor.mockResolvedValueOnce(null);
    expect(await emailProvider.verify(baseCtx, '123456')).toBe(false);
  });

  it('returns false and deletes challenge on TTL expiry', async () => {
    const expiredRow = makeChallengeRow({ createdAt: Date.now() - (CODE_TTL_S + 60) * 1000 });
    mockGetTwoFactor.mockResolvedValueOnce(expiredRow);
    expect(await emailProvider.verify(baseCtx, '123456')).toBe(false);
    expect(mockDeleteTwoFactor).toHaveBeenCalledOnce();
  });

  it('returns false and deletes challenge when attempts exhausted', async () => {
    const exhaustedRow = makeChallengeRow({ attempts: MAX_ATTEMPTS });
    mockGetTwoFactor.mockResolvedValueOnce(exhaustedRow);
    expect(await emailProvider.verify(baseCtx, 'wrong')).toBe(false);
    expect(mockDeleteTwoFactor).toHaveBeenCalledOnce();
  });

  it('increments attempts on wrong code (not yet at limit)', async () => {
    const row = makeChallengeRow({ code: '999999', attempts: 0 });
    mockGetTwoFactor.mockResolvedValueOnce(row);
    expect(await emailProvider.verify(baseCtx, '000000')).toBe(false);
    // Should upsert with attempts=1, not delete.
    expect(mockDeleteTwoFactor).not.toHaveBeenCalled();
    expect(mockUpsertTwoFactor).toHaveBeenCalledOnce();
    const upsertArg = (mockUpsertTwoFactor.mock.calls[0] as unknown[])[1] as TwoFactorRow;
    const stored = JSON.parse(upsertArg.data) as { attempts: number };
    expect(stored.attempts).toBe(1);
  });

  it('deletes challenge on 3rd wrong attempt (max attempts)', async () => {
    const row = makeChallengeRow({ code: '999999', attempts: MAX_ATTEMPTS - 1 });
    mockGetTwoFactor.mockResolvedValueOnce(row);
    expect(await emailProvider.verify(baseCtx, '000000')).toBe(false);
    expect(mockDeleteTwoFactor).toHaveBeenCalledOnce();
    expect(mockUpsertTwoFactor).not.toHaveBeenCalled();
  });

  it('returns true and deletes challenge on correct code', async () => {
    const row = makeChallengeRow({ code: '123456', attempts: 0 });
    mockGetTwoFactor.mockResolvedValueOnce(row);
    expect(await emailProvider.verify(baseCtx, '123456')).toBe(true);
    expect(mockDeleteTwoFactor).toHaveBeenCalledOnce();
    expect(mockUpsertTwoFactor).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// 5. handleSendEmailLogin
// ---------------------------------------------------------------------------

describe('handleSendEmailLogin', () => {
  beforeEach(() => vi.clearAllMocks());

  function makeRequest(body: Record<string, string>): Request {
    return new Request('https://example.com/api/two-factor/send-email-login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '127.0.0.1' },
      body: new URLSearchParams(body).toString(),
    });
  }

  it('returns 200 when Email 2FA not configured (anti-enumeration)', async () => {
    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'a@b.com', masterPasswordHash: 'hash' }),
      fakeEnvNoEmail as typeof fakeEnv
    );
    expect(resp.status).toBe(200);
    // Fetch should NOT be called (no sender configured).
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns 200 for unknown email (anti-enumeration)', async () => {
    mockStorageGetUser.mockResolvedValueOnce(null);
    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'nobody@example.com', masterPasswordHash: 'hash' }),
      fakeEnv as typeof fakeEnv
    );
    expect(resp.status).toBe(200);
  });

  it('returns 200 on wrong masterPasswordHash (anti-enumeration)', async () => {
    mockStorageGetUser.mockResolvedValueOnce(makeUser());
    mockAuthVerify.mockResolvedValueOnce(false);
    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'test@example.com', masterPasswordHash: 'wrong' }),
      fakeEnv as typeof fakeEnv
    );
    expect(resp.status).toBe(200);
    // Failed login should be recorded.
    expect(mockRecordFailedLogin).toHaveBeenCalled();
  });

  it('returns 200 when user has no Email 2FA enrollment', async () => {
    mockStorageGetUser.mockResolvedValueOnce(makeUser());
    mockAuthVerify.mockResolvedValueOnce(true);
    // getTwoFactor returns null (not enrolled).
    mockGetTwoFactor.mockResolvedValueOnce(null);
    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'test@example.com', masterPasswordHash: 'hash' }),
      fakeEnv as typeof fakeEnv
    );
    expect(resp.status).toBe(200);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('sends code and returns 200 when all conditions met', async () => {
    mockStorageGetUser.mockResolvedValueOnce(makeUser());
    mockAuthVerify.mockResolvedValueOnce(true);
    mockGetTwoFactor.mockResolvedValueOnce(makeEnrollmentRow('user@example.com'));
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));

    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'test@example.com', masterPasswordHash: 'hash' }),
      fakeEnv as typeof fakeEnv
    );
    expect(resp.status).toBe(200);
    expect(mockUpsertTwoFactor).toHaveBeenCalledOnce(); // code stored
    expect(mockFetch).toHaveBeenCalledOnce();           // code sent via HTTP backend
  });

  it('returns 500 when email API fails (send failure must not be swallowed)', async () => {
    mockStorageGetUser.mockResolvedValueOnce(makeUser());
    mockAuthVerify.mockResolvedValueOnce(true);
    mockGetTwoFactor.mockResolvedValueOnce(makeEnrollmentRow());
    // Both retry attempts fail.
    mockFetch
      .mockResolvedValueOnce(new Response('{"message":"rate limit"}', { status: 429 }))
      .mockResolvedValueOnce(new Response('{"message":"rate limit"}', { status: 429 }));

    const resp = await handleSendEmailLogin(
      makeRequest({ email: 'test@example.com', masterPasswordHash: 'hash' }),
      fakeEnv as typeof fakeEnv
    );
    expect(resp.status).toBe(500);
    const body = await resp.json() as { Message: string };
    expect(body.Message).toMatch(/Failed to send/);
  });
});

// ---------------------------------------------------------------------------
// 6. maskEmail helper
// ---------------------------------------------------------------------------

describe('maskEmail', () => {
  it('masks a standard email address', () => {
    expect(maskEmail('user@example.com')).toBe('u***@e***.com');
  });

  it('masks short local part', () => {
    expect(maskEmail('a@b.org')).toBe('a***@b***.org');
  });

  it('handles email without dot in domain', () => {
    const result = maskEmail('test@localhost');
    expect(result).toContain('***');
  });
});

// ---------------------------------------------------------------------------
// 7. generateNumericCode helper
// ---------------------------------------------------------------------------

describe('generateNumericCode', () => {
  it('generates a 6-character all-digit string', () => {
    for (let i = 0; i < 20; i++) {
      const code = generateNumericCode();
      expect(code).toHaveLength(6);
      expect(/^\d{6}$/.test(code)).toBe(true);
    }
  });

  it('generates different codes on repeated calls', () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateNumericCode()));
    // With 1M possibilities, 50 calls should almost certainly produce >1 unique code.
    expect(codes.size).toBeGreaterThan(1);
  });
});

// ---------------------------------------------------------------------------
// 8. handleGetEmailTwoFactor — available flag reflects server configuration
// ---------------------------------------------------------------------------

describe('handleGetEmailTwoFactor — available flag', () => {
  function makeGetRequest(): Request {
    return new Request('https://example.com/api/two-factor/email', { method: 'GET' });
  }

  function makeEnv(configured: boolean): import('../../types').Env {
    return {
      DB: {} as D1Database,
      JWT_SECRET: 'test',
      ...(configured ? {
        MFA_EMAIL_HTTP_ENDPOINT: 'http://localhost:9876/send',
        MFA_EMAIL_FROM: 'noreply@example.com',
      } : {}),
    } as unknown as import('../../types').Env;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    mockStorageGetUserById.mockResolvedValue(makeUser());
    mockGetTwoFactor.mockResolvedValue(null);
  });

  it('returns available=true when HTTP endpoint and MFA_EMAIL_FROM are set', async () => {
    const resp = await handleGetEmailTwoFactor(makeGetRequest(), makeEnv(true), 'user-001');
    expect(resp.status).toBe(200);
    const body = await resp.json() as { available: boolean; enabled: boolean };
    expect(body.available).toBe(true);
    expect(body.enabled).toBe(false); // no enrollment row
  });

  it('returns available=false when email backend env vars are missing', async () => {
    const resp = await handleGetEmailTwoFactor(makeGetRequest(), makeEnv(false), 'user-001');
    expect(resp.status).toBe(200);
    const body = await resp.json() as { available: boolean; enabled: boolean };
    expect(body.available).toBe(false);
  });

  it('returns available=true for CF-only deployment (EMAIL binding + MFA_EMAIL_FROM)', async () => {
    const cfEnv = {
      DB: {} as D1Database,
      JWT_SECRET: 'test',
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: { send: vi.fn().mockResolvedValue({ messageId: 'cf-001' }) },
    } as unknown as import('../../types').Env;
    mockStorageGetUserById.mockResolvedValue(makeUser());
    mockGetTwoFactor.mockResolvedValue(null);
    const resp = await handleGetEmailTwoFactor(makeGetRequest(), cfEnv, 'user-001');
    const body = await resp.json() as { available: boolean };
    expect(body.available).toBe(true);
  });

  it('returns enabled=true when enrollment row exists and available=true', async () => {
    mockGetTwoFactor.mockResolvedValue(makeEnrollmentRow('test@example.com'));
    const resp = await handleGetEmailTwoFactor(makeGetRequest(), makeEnv(true), 'user-001');
    const body = await resp.json() as { available: boolean; enabled: boolean };
    expect(body.available).toBe(true);
    expect(body.enabled).toBe(true);
  });
});
