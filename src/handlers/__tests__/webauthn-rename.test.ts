/**
 * webauthn-rename.test.ts
 *
 * Handler-level tests for:
 *   - PUT /api/two-factor/webauthn  (rename a credential)
 *   - DELETE /api/two-factor/webauthn without credentialId (disable all)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { User } from '../../types';
import type { WebAuthnCredential } from '../../services/two-factor/webauthn-provider';

// ---------------------------------------------------------------------------
// Mocks (must be registered before any import of the modules under test)
// ---------------------------------------------------------------------------

const mockRenameCredential = vi.fn<() => Promise<boolean>>();
const mockDisableAllWebAuthn = vi.fn<() => Promise<void>>(() => Promise.resolve());
const mockDeleteCredential = vi.fn<() => Promise<boolean>>(() => Promise.resolve(true));
const mockListCredentials = vi.fn<() => WebAuthnCredential[]>(() => []);
const mockCompleteRegistration = vi.fn<() => Promise<WebAuthnCredential>>(() =>
  Promise.resolve({ id: 'cred-1', name: 'Key', createdAt: '', publicKeyCbor: 'AA==', signCount: 0 })
);

vi.mock('../../services/two-factor/webauthn-provider', () => ({
  renameCredential: (...args: unknown[]) => mockRenameCredential(...(args as [])),
  disableAllWebAuthn: (...args: unknown[]) => mockDisableAllWebAuthn(...(args as [])),
  deleteCredential: (...args: unknown[]) => mockDeleteCredential(...(args as [])),
  listCredentials: (...args: unknown[]) => mockListCredentials(...(args as [])),
  generateRegistrationChallenge: vi.fn(() => Promise.resolve({})),
  completeRegistration: (...args: unknown[]) => mockCompleteRegistration(...(args as [])),
  WEBAUTHN_REG_CHALLENGE_ATYPE: 1003,
  WEBAUTHN_LOGIN_CHALLENGE_ATYPE: 1004,
}));

vi.mock('../../services/audit-events', () => ({
  auditRequestMetadata: vi.fn(() => ({})),
  safeWriteAuditEvent: vi.fn(() => Promise.resolve()),
  writeAuditEvent: vi.fn(() => Promise.resolve()),
}));

const mockGetUser = vi.fn<() => Promise<User | null>>();
const mockGetTwoFactorsByUserId = vi.fn(() => Promise.resolve([]));
const mockSaveUser = vi.fn(() => Promise.resolve());

vi.mock('../../services/storage', () => ({
  StorageService: function () {
    return {
      getUserById: mockGetUser,
      getTwoFactorsByUserId: mockGetTwoFactorsByUserId,
      saveUser: mockSaveUser,
    };
  },
}));

const mockAuthVerify = vi.fn<() => Promise<boolean>>(() => Promise.resolve(true));
vi.mock('../../services/auth', () => ({
  AuthService: function () {
    return { verifyPassword: mockAuthVerify };
  },
}));

vi.mock('../../services/two-factor/email-provider', () => ({
  EMAIL_ENROLLMENT_ATYPE: 1,
  EMAIL_LOGIN_CHALLENGE_ATYPE: 1001,
  generateNumericCode: vi.fn(() => '123456'),
  maskEmail: vi.fn((e: string) => e),
  CODE_TTL_S: 600,
}));

vi.mock('../../services/email-sender', () => ({
  buildEmailSenderFromEnv: vi.fn(() => null),
}));

vi.mock('../../services/ratelimit', () => ({
  RateLimitService: function () { return { checkLoginAttempt: vi.fn(() => Promise.resolve({ allowed: true })) }; },
  getClientIdentifier: vi.fn(() => '127.0.0.1'),
}));

vi.mock('../../utils/user-decryption', () => ({
  buildAccountKeys: vi.fn(() => ({})),
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

import { handleRenameWebAuthn, handleDeleteWebAuthn, handleRegisterWebAuthn } from '../accounts';

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
    totpRecoveryCode: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
  };
}

const fakeEnv = { DB: {} as D1Database, JWT_SECRET: 'test' } as unknown as import('../../types').Env;

function makeJsonRequest(body: unknown, method = 'PUT'): Request {
  return new Request('https://example.com/api/two-factor/webauthn', {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// Tests: handleRenameWebAuthn
// ---------------------------------------------------------------------------

describe('handleRenameWebAuthn', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue(makeUser());
    mockGetTwoFactorsByUserId.mockResolvedValue([]);
    mockListCredentials.mockReturnValue([]);
  });

  it('returns 200 with updated keys when credential exists', async () => {
    mockRenameCredential.mockResolvedValue(true);
    mockListCredentials.mockReturnValue([
      { id: 'cred-1', name: 'Renamed', createdAt: '2024-01-01T00:00:00Z', publicKeyCbor: 'AABB', signCount: 0 },
    ]);

    const req = makeJsonRequest({ credentialId: 'cred-1', name: 'Renamed' });
    const resp = await handleRenameWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(200);
    const body = await resp.json() as { keys: Array<{ id: string; name: string }>; object: string };
    expect(body.object).toBe('twoFactorWebAuthn');
    expect(body.keys[0]?.name).toBe('Renamed');
  });

  it('returns 404 when credential not found', async () => {
    mockRenameCredential.mockResolvedValue(false);
    const req = makeJsonRequest({ credentialId: 'nonexistent', name: 'Test' });
    const resp = await handleRenameWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(404);
  });

  it('returns 400 when credentialId is missing', async () => {
    const req = makeJsonRequest({ name: 'Test' });
    const resp = await handleRenameWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(400);
  });

  it('returns 400 when name is empty', async () => {
    const req = makeJsonRequest({ credentialId: 'cred-1', name: '' });
    const resp = await handleRenameWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(400);
  });

  it('returns 404 when user not found', async () => {
    mockGetUser.mockResolvedValue(null);
    const req = makeJsonRequest({ credentialId: 'cred-1', name: 'Test' });
    const resp = await handleRenameWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Tests: handleDeleteWebAuthn — bulk disable (no credentialId)
// ---------------------------------------------------------------------------

describe('handleDeleteWebAuthn — bulk disable', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUser.mockResolvedValue(makeUser());
    mockAuthVerify.mockResolvedValue(true);
    mockGetTwoFactorsByUserId.mockResolvedValue([]);
    mockListCredentials.mockReturnValue([]);
  });

  it('returns 200 with empty keys when no credentialId and valid masterPasswordHash', async () => {
    const req = makeJsonRequest({ masterPasswordHash: 'validhash' }, 'DELETE');
    const resp = await handleDeleteWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(200);
    const body = await resp.json() as { keys: unknown[]; object: string };
    expect(body.object).toBe('twoFactorWebAuthn');
    expect(body.keys).toEqual([]);
    expect(mockDisableAllWebAuthn).toHaveBeenCalledWith(fakeEnv.DB, 'user-001');
  });

  it('returns 400 when masterPasswordHash is missing', async () => {
    const req = makeJsonRequest({}, 'DELETE');
    const resp = await handleDeleteWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(400);
  });

  it('returns 400 when masterPasswordHash is wrong', async () => {
    mockAuthVerify.mockResolvedValue(false);
    const req = makeJsonRequest({ masterPasswordHash: 'wronghash' }, 'DELETE');
    const resp = await handleDeleteWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Regression: handleRegisterWebAuthn must forward transports + attachment
// ---------------------------------------------------------------------------
//
// P0 bug (fixed): handler was building the completeRegistration body without
// forwarding body.transports / body.attachment, so all newly registered keys
// were stored without those fields and the type-badge (getKeyType) always fell
// through to "generic". This suite locks that fix in place.

describe('handleRegisterWebAuthn — transports/attachment forwarding', () => {
  function makeRegisterRequest(extra: Record<string, unknown> = {}): Request {
    return new Request('https://example.com/api/two-factor/webauthn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: 'cred-abc',
        rawId: 'cred-abc',
        type: 'public-key',
        response: { attestationObject: 'AAAA', clientDataJSON: 'BBBB' },
        name: 'My YubiKey',
        masterPasswordHash: 'validhash',
        ...extra,
      }),
    });
  }

  beforeEach(() => {
    vi.clearAllMocks();
    // Use a user that already has a recovery code so the save-user branch is skipped.
    mockGetUser.mockResolvedValue({ ...makeUser(), totpRecoveryCode: 'EXISTING-CODE' });
    mockAuthVerify.mockResolvedValue(true);
    mockGetTwoFactorsByUserId.mockResolvedValue([]);
    mockListCredentials.mockReturnValue([]);
  });

  it('forwards transports and attachment to completeRegistration', async () => {
    const req = makeRegisterRequest({ transports: ['usb', 'nfc'], attachment: 'cross-platform' });
    const resp = await handleRegisterWebAuthn(req, fakeEnv, 'user-001');
    expect(resp.status).toBe(200);
    expect(mockCompleteRegistration).toHaveBeenCalledWith(
      fakeEnv.DB,
      expect.objectContaining({ id: 'user-001' }),
      expect.objectContaining({ transports: ['usb', 'nfc'], attachment: 'cross-platform' }),
      fakeEnv,
    );
  });

  it('forwards attachment=platform (Touch ID / Face ID)', async () => {
    const req = makeRegisterRequest({ transports: ['internal'], attachment: 'platform' });
    await handleRegisterWebAuthn(req, fakeEnv, 'user-001');
    expect(mockCompleteRegistration).toHaveBeenCalledWith(
      fakeEnv.DB,
      expect.anything(),
      expect.objectContaining({ transports: ['internal'], attachment: 'platform' }),
      fakeEnv,
    );
  });

  it('passes transports=undefined and attachment=undefined when absent from request', async () => {
    const req = makeRegisterRequest(); // no transports / attachment
    await handleRegisterWebAuthn(req, fakeEnv, 'user-001');
    expect(mockCompleteRegistration).toHaveBeenCalledWith(
      fakeEnv.DB,
      expect.anything(),
      expect.objectContaining({ transports: undefined, attachment: undefined }),
      fakeEnv,
    );
  });

  it('ignores non-array transports (passes undefined)', async () => {
    const req = makeRegisterRequest({ transports: 'usb' }); // string, not array
    await handleRegisterWebAuthn(req, fakeEnv, 'user-001');
    expect(mockCompleteRegistration).toHaveBeenCalledWith(
      fakeEnv.DB,
      expect.anything(),
      expect.objectContaining({ transports: undefined }),
      fakeEnv,
    );
  });
});
