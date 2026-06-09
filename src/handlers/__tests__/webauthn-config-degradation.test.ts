/**
 * webauthn-config-degradation.test.ts
 *
 * Regression tests for #5: GET /api/two-factor/webauthn must NOT 500 when the
 * WebAuthn relying-party config (WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN) is missing.
 *
 * The pre-existing handler tests mock generateRegistrationChallenge to resolve,
 * so extractRpIdAndOrigin never runs and the un-configured branch was never
 * exercised — that is exactly the gap that let the production 500 ship. These
 * tests drive the real degradation logic by making the challenge builders throw:
 *   - WebAuthnConfigError  → graceful degrade (GET 200 / reenable 400)
 *   - any other error      → still surfaces as 500 (no silent swallow of real bugs)
 *
 * WebAuthnConfigError is imported from the real passkey module (NOT mocked) so the
 * handler's `instanceof WebAuthnConfigError` checks match the instances thrown here.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { User } from '../../types';
import type { WebAuthnCredential } from '../../services/two-factor/webauthn-provider';
import { WebAuthnConfigError } from '../../utils/passkey';

// ---------------------------------------------------------------------------
// Mocks (must be registered before any import of the modules under test)
// ---------------------------------------------------------------------------

const mockGenerateRegistrationChallenge = vi.fn<() => Promise<Record<string, unknown>>>(
  () => Promise.resolve({ status: 'ok', errorMessage: '', challenge: 'abc' })
);
const mockBuildChallenge = vi.fn<() => Promise<Record<string, unknown>>>(
  () => Promise.resolve({ status: 'ok', errorMessage: '', challenge: 'abc', allowCredentials: [] })
);
const mockListCredentials = vi.fn<() => WebAuthnCredential[]>(() => []);
const mockReenableAllWebAuthn = vi.fn<() => Promise<boolean>>(() => Promise.resolve(true));

vi.mock('../../services/two-factor/webauthn-provider', () => ({
  generateRegistrationChallenge: (...args: unknown[]) => mockGenerateRegistrationChallenge(...(args as [])),
  listCredentials: (...args: unknown[]) => mockListCredentials(...(args as [])),
  reenableAllWebAuthn: (...args: unknown[]) => mockReenableAllWebAuthn(...(args as [])),
  webAuthnProvider: {
    verify: vi.fn(() => Promise.resolve(true)),
    buildChallenge: (...args: unknown[]) => mockBuildChallenge(...(args as [])),
  },
  // Unused by the handlers under test but referenced elsewhere in the module surface.
  renameCredential: vi.fn(() => Promise.resolve(true)),
  disableAllWebAuthn: vi.fn(() => Promise.resolve()),
  deleteCredential: vi.fn(() => Promise.resolve(true)),
  completeRegistration: vi.fn(() => Promise.resolve({ id: 'c', name: 'k', createdAt: '', publicKeyCbor: 'AA==', signCount: 0 })),
  WEBAUTHN_REG_CHALLENGE_ATYPE: 1003,
  WEBAUTHN_LOGIN_CHALLENGE_ATYPE: 1004,
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
  writeAuditEvent: vi.fn(() => Promise.resolve()),
}));

const mockGetUser = vi.fn<() => Promise<User | null>>();
const mockGetTwoFactorsByUserId = vi.fn<() => Promise<Array<Record<string, unknown>>>>(() => Promise.resolve([]));

vi.mock('../../services/storage', () => ({
  StorageService: function () {
    return {
      getUserById: mockGetUser,
      getTwoFactorsByUserId: mockGetTwoFactorsByUserId,
      deleteRefreshTokensByUserId: vi.fn(() => Promise.resolve()),
    };
  },
}));

const mockAuthVerify = vi.fn<() => Promise<boolean>>(() => Promise.resolve(true));
vi.mock('../../services/auth', () => ({
  AuthService: Object.assign(
    function () { return { verifyPassword: (...args: Parameters<typeof mockAuthVerify>) => mockAuthVerify(...args) }; },
    { invalidateUserCache: vi.fn() }
  ),
}));

vi.mock('../../services/two-factor/email-provider', () => ({
  EMAIL_ENROLLMENT_ATYPE: 1,
  EMAIL_LOGIN_CHALLENGE_ATYPE: 1002,
  generateNumericCode: vi.fn(() => '123456'),
  maskEmail: vi.fn((e: string) => e),
  CODE_TTL_S: 600,
}));

vi.mock('../../services/email-sender', () => ({
  buildEmailSenderFromEnv: vi.fn(() => null),
}));

vi.mock('../../services/storage-two-factor-repo', () => ({
  getTwoFactor: vi.fn(() => Promise.resolve(null)),
  upsertTwoFactor: vi.fn(() => Promise.resolve()),
  deleteTwoFactor: vi.fn(() => Promise.resolve(true)),
  getTwoFactorsByUserId: vi.fn(() => Promise.resolve([])),
}));

// ---------------------------------------------------------------------------
// Import handlers under test (after mocks)
// ---------------------------------------------------------------------------

import { handleGetWebAuthnChallenge, handleReenableWebAuthn } from '../accounts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUser(id = 'user-001'): User {
  return {
    id,
    email: 'test@example.com',
    name: null,
    masterPasswordHint: null,
    masterPasswordHash: 'hash',
    key: 'key',
    privateKey: null,
    publicKey: null,
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpEnabled: false,
    totpRecoveryCode: null,
    totpLastCounter: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
  };
}

// Env intentionally WITHOUT WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN — this is the
// un-configured production scenario the regression guards.
const unconfiguredEnv = { DB: {} as D1Database, JWT_SECRET: 'test' } as unknown as import('../../types').Env;

const RETAINED_CREDENTIAL: WebAuthnCredential = {
  id: 'cred-1',
  name: 'YubiKey',
  createdAt: '2024-01-01T00:00:00Z',
  publicKeyCbor: 'AABB',
  signCount: 3,
  transports: ['usb'],
  attachment: 'cross-platform',
};

function makeGetRequest(): Request {
  return new Request('https://example.com/api/two-factor/webauthn', { method: 'GET' });
}

function makeReenableRequest(body: Record<string, unknown>): Request {
  return new Request('https://example.com/api/two-factor/webauthn/reenable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// GET /api/two-factor/webauthn — graceful degradation
// ---------------------------------------------------------------------------

describe('handleGetWebAuthnChallenge — WebAuthn config degradation (#5)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue(makeUser());
    mockGetTwoFactorsByUserId.mockResolvedValue([
      { atype: 7, enabled: true } as Record<string, unknown>,
    ]);
    mockListCredentials.mockReturnValue([RETAINED_CREDENTIAL]);
  });

  it('returns 200 with keys + enabled + unavailable registration marker when env is unconfigured (no 500)', async () => {
    mockGenerateRegistrationChallenge.mockRejectedValueOnce(
      new WebAuthnConfigError('WebAuthn is not configured: WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN must both be set')
    );

    const resp = await handleGetWebAuthnChallenge(makeGetRequest(), unconfiguredEnv, 'user-001');

    expect(resp.status).toBe(200);
    const body = await resp.json() as {
      status?: string;
      errorMessage?: string;
      enabled?: boolean;
      keys?: Array<{ id: string }>;
      object?: string;
    };
    expect(body.status).toBe('error');
    expect(body.errorMessage).toBe('WebAuthn not configured');
    expect(body.enabled).toBe(true);
    expect(body.object).toBe('twoFactorWebAuthn');
    expect(body.keys).toHaveLength(1);
    expect(body.keys?.[0]?.id).toBe('cred-1');
  });

  it('reflects enabled=false (soft-disabled) while still listing retained keys when unconfigured', async () => {
    mockGetTwoFactorsByUserId.mockResolvedValue([
      { atype: 7, enabled: false } as Record<string, unknown>,
    ]);
    mockGenerateRegistrationChallenge.mockRejectedValueOnce(
      new WebAuthnConfigError('WEBAUTHN_ORIGIN is not a valid URL')
    );

    const resp = await handleGetWebAuthnChallenge(makeGetRequest(), unconfiguredEnv, 'user-001');

    expect(resp.status).toBe(200);
    const body = await resp.json() as { enabled?: boolean; keys?: unknown[]; status?: string };
    expect(body.enabled).toBe(false);
    expect(body.status).toBe('error');
    expect(body.keys).toHaveLength(1);
  });

  it('still 500s when generateRegistrationChallenge throws a NON-config error (real failure not swallowed)', async () => {
    // Red line against silent failure: a DB/parse/etc. error must NOT be masked as a
    // benign "not configured" response — it must surface as a 500.
    mockGenerateRegistrationChallenge.mockRejectedValueOnce(new Error('D1 connection lost'));

    await expect(
      handleGetWebAuthnChallenge(makeGetRequest(), unconfiguredEnv, 'user-001')
    ).rejects.toThrow('D1 connection lost');
  });

  it('returns the normal challenge (status:ok) unchanged when env IS configured', async () => {
    // Baseline: configured path is untouched — generateRegistrationChallenge resolves
    // with status:'ok' and the handler forwards it alongside keys/enabled.
    mockGenerateRegistrationChallenge.mockResolvedValueOnce({ status: 'ok', errorMessage: '', challenge: 'xyz' });

    const resp = await handleGetWebAuthnChallenge(makeGetRequest(), unconfiguredEnv, 'user-001');

    expect(resp.status).toBe(200);
    const body = await resp.json() as { status?: string; challenge?: string; object?: string; keys?: unknown[] };
    expect(body.status).toBe('ok');
    expect(body.challenge).toBe('xyz');
    expect(body.object).toBe('twoFactorWebAuthn');
    expect(body.keys).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// POST /api/two-factor/webauthn/reenable phase 1 — config degradation
// ---------------------------------------------------------------------------

describe('handleReenableWebAuthn — phase 1 config degradation (#5)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue(makeUser());
    mockAuthVerify.mockResolvedValue(true);
    mockGetTwoFactorsByUserId.mockResolvedValue([
      { atype: 7, enabled: false } as Record<string, unknown>,
    ]);
    mockListCredentials.mockReturnValue([RETAINED_CREDENTIAL]);
    mockReenableAllWebAuthn.mockResolvedValue(true);
  });

  it('returns 400 (not 500) on phase 1 when env is unconfigured', async () => {
    mockBuildChallenge.mockRejectedValueOnce(
      new WebAuthnConfigError('WebAuthn is not configured: WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN must both be set')
    );

    const resp = await handleReenableWebAuthn(
      makeReenableRequest({ masterPasswordHash: 'validhash' }),
      unconfiguredEnv,
      'user-001'
    );

    expect(resp.status).toBe(400);
    // Must NOT re-enable the credentials when the challenge could not be issued.
    expect(mockReenableAllWebAuthn).not.toHaveBeenCalled();
  });

  it('still 500s on phase 1 when buildChallenge throws a NON-config error', async () => {
    mockBuildChallenge.mockRejectedValueOnce(new Error('D1 connection lost'));

    await expect(
      handleReenableWebAuthn(
        makeReenableRequest({ masterPasswordHash: 'validhash' }),
        unconfiguredEnv,
        'user-001'
      )
    ).rejects.toThrow('D1 connection lost');
    expect(mockReenableAllWebAuthn).not.toHaveBeenCalled();
  });

  it('returns the challenge (200) on phase 1 when env IS configured', async () => {
    mockBuildChallenge.mockResolvedValueOnce({ status: 'ok', challenge: 'xyz', allowCredentials: [] });

    const resp = await handleReenableWebAuthn(
      makeReenableRequest({ masterPasswordHash: 'validhash' }),
      unconfiguredEnv,
      'user-001'
    );

    expect(resp.status).toBe(200);
    const body = await resp.json() as { object?: string; challenge?: string };
    expect(body.object).toBe('twoFactorWebAuthnReenableChallenge');
    expect(body.challenge).toBe('xyz');
    // Phase 1 only issues the challenge; it must not re-enable yet.
    expect(mockReenableAllWebAuthn).not.toHaveBeenCalled();
  });
});
