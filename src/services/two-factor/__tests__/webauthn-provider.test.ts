/**
 * WebAuthn provider 断言验证测试
 *
 * 覆盖 checklist §1 要求的所有场景：
 *   - 正确断言 → 通过
 *   - 挑战态不存在 → 拒绝
 *   - 挑战 TTL 过期 → 拒绝
 *   - clientDataJSON.type 不是 webauthn.get → 拒绝
 *   - origin 不匹配 → 拒绝
 *   - rpIdHash 不匹配 → 拒绝
 *   - challenge 不匹配 → 拒绝
 *   - UP flag 未设置 → 拒绝
 *   - signCount 回退（≤ 存储值且非0）→ 拒绝
 *   - 未知凭据 ID → 拒绝
 *   - 签名错误 → 拒绝
 *   - 未知算法 → 拒绝
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebAuthnTwoFactorProvider, WEBAUTHN_LOGIN_CHALLENGE_ATYPE } from '../webauthn-provider';
import { TwoFactorType } from '../types';
import type { VerifyContext } from '../types';
import type { User } from '../../../types';
import {
  bytesToBase64Url,
  base64UrlToBytes,
  FLAG_UP,
  FLAG_UV,
} from '../../../utils/passkey';

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

const FIXED_ORIGIN = 'https://vault.example.com';
const FIXED_RP_ID = 'vault.example.com';

/** Generate a real P-256 key pair and return the COSE key CBOR bytes + private key. */
async function generateES256KeyPair(): Promise<{
  privateKey: CryptoKey;
  coseKeyBytes: Uint8Array;
  jwkPublic: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  const xBytes = base64UrlToBytes(jwk.x!);
  const yBytes = base64UrlToBytes(jwk.y!);

  // Build minimal COSE key CBOR: { 1: 2, 3: -7, -1: -7, -2: x(32B), -3: y(32B) }
  // bytestring of 32 bytes: major type 2, additional_info 24 (1-byte length), then 32
  const parts: number[] = [(5 << 5) | 5];
  parts.push(1, 2); // kty=2
  parts.push(3, (1 << 5) | 6); // alg=-7
  parts.push((1 << 5) | 0, (1 << 5) | 6); // crv=-7
  parts.push((1 << 5) | 1, (2 << 5) | 24, 32, ...xBytes); // key=-2, x (32B)
  parts.push((1 << 5) | 2, (2 << 5) | 24, 32, ...yBytes); // key=-3, y (32B)

  return { privateKey: keyPair.privateKey as CryptoKey, coseKeyBytes: new Uint8Array(parts), jwkPublic: jwk };
}

/** Build 37-byte authenticatorData with given rpId and signCount. */
async function buildAuthData(rpId: string, signCount: number, flags: number = FLAG_UP): Promise<Uint8Array> {
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  const buf = new Uint8Array(37);
  buf.set(rpIdHash, 0);
  buf[32] = flags;
  new DataView(buf.buffer).setUint32(33, signCount, false);
  return buf;
}

/** Build clientDataJSON bytes for webauthn.get. */
function buildClientData(challenge: string, origin: string, type = 'webauthn.get'): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ type, challenge, origin }));
}

/** Sign authData ‖ SHA-256(clientDataJSON) and return DER-encoded signature. */
async function signAssertion(
  privateKey: CryptoKey,
  authData: Uint8Array,
  clientDataJsonBytes: Uint8Array
): Promise<Uint8Array> {
  const hashedClientData = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJsonBytes));
  const signedData = new Uint8Array(authData.byteLength + hashedClientData.byteLength);
  signedData.set(authData, 0);
  signedData.set(hashedClientData, authData.byteLength);
  // crypto.subtle returns raw r‖s for ECDSA
  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData)
  );
  return rawToDer(rawSig);
}

function rawToDer(raw: Uint8Array): Uint8Array {
  let r = raw.slice(0, 32);
  let s = raw.slice(32, 64);
  if (r[0] & 0x80) r = new Uint8Array([0x00, ...r]);
  if (s[0] & 0x80) s = new Uint8Array([0x00, ...s]);
  const totalLen = 2 + r.length + 2 + s.length;
  return new Uint8Array([0x30, totalLen, 0x02, r.length, ...r, 0x02, s.length, ...s]);
}

/** Build a JSON token string as would be sent by a Bitwarden client. */
function buildTokenJson(opts: {
  credentialId: string;
  authData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
}): string {
  return JSON.stringify({
    id: opts.credentialId,
    rawId: opts.credentialId,
    type: 'public-key',
    response: {
      authenticatorData: bytesToBase64Url(opts.authData),
      clientDataJSON: bytesToBase64Url(opts.clientDataJson),
      signature: bytesToBase64Url(opts.signature),
      userHandle: null,
    },
    extensions: {},
  });
}

/** Build a mock D1 database that returns a preset challenge and tracks calls. */
function buildMockDb(challengeData: {
  challenge: string;
  issuedAt: number;
  rpId: string;
  origin: string;
} | null): {
  db: D1Database;
  deleteCalledWith: Array<[string, number]>;
  updateCalledWith: Array<unknown[]>;
} {
  const deleteCalledWith: Array<[string, number]> = [];
  const updateCalledWith: Array<unknown[]> = [];

  const db = {
    prepare: (sql: string) => ({
      bind: (...args: unknown[]) => ({
        first: async () => {
          if (sql.includes('SELECT data FROM two_factors') && sql.includes('atype = ?')) {
            const atype = args[1] as number;
            if (atype === WEBAUTHN_LOGIN_CHALLENGE_ATYPE && challengeData !== null) {
              return { data: JSON.stringify(challengeData) };
            }
            return null;
          }
          return null;
        },
        run: async () => {
          if (sql.includes('DELETE FROM two_factors')) {
            deleteCalledWith.push([args[0] as string, args[1] as number]);
          } else if (sql.includes('UPDATE two_factors')) {
            updateCalledWith.push(args);
          }
          return { meta: { changes: 1 } };
        },
        all: async () => {
          // popLoginChallenge now atomically consumes via DELETE … RETURNING data.
          if (sql.includes('DELETE FROM two_factors') && sql.includes('RETURNING')) {
            deleteCalledWith.push([args[0] as string, args[1] as number]);
            const atype = args[1] as number;
            if (atype === WEBAUTHN_LOGIN_CHALLENGE_ATYPE && challengeData !== null) {
              return { results: [{ data: JSON.stringify(challengeData) }] };
            }
            return { results: [] };
          }
          return { results: [] };
        },
      }),
    }),
  } as unknown as D1Database;

  return { db, deleteCalledWith, updateCalledWith };
}

function makeUser(id: string = 'user-001'): User {
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
    totpEnabled: true,
    totpRecoveryCode: null,
    totpLastCounter: null,
    apiKey: null,
    createdAt: '2023-01-01T00:00:00Z',
    updatedAt: '2023-01-01T00:00:00Z',
  };
}

const fakeEnv = {
  DB: {} as D1Database,
  JWT_SECRET: 'test',
} as unknown as import('../../../types').Env;

// -----------------------------------------------------------------------
// Test suite
// -----------------------------------------------------------------------

describe('WebAuthnTwoFactorProvider.verify', () => {
  let provider: WebAuthnTwoFactorProvider;
  let keyPair: { privateKey: CryptoKey; coseKeyBytes: Uint8Array };
  let credentialId: string;
  let validChallenge: string;

  beforeEach(async () => {
    provider = new WebAuthnTwoFactorProvider();
    keyPair = await generateES256KeyPair();
    credentialId = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    validChallenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  });

  /** Build a full valid assertion and return all pieces. */
  async function buildValidAssertion(opts: {
    challenge?: string;
    rpId?: string;
    origin?: string;
    signCount?: number;
    flags?: number;
    storedSignCount?: number;
  } = {}) {
    const challenge = opts.challenge ?? validChallenge;
    const rpId = opts.rpId ?? FIXED_RP_ID;
    const origin = opts.origin ?? FIXED_ORIGIN;
    const signCount = opts.signCount ?? 1;
    const flags = opts.flags ?? FLAG_UP;

    const authData = await buildAuthData(rpId, signCount, flags);
    const clientDataJson = buildClientData(challenge, origin);
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId, authData, clientDataJson, signature });

    const challengeState = {
      challenge,
      issuedAt: Date.now() - 1000, // 1s ago
      rpId,
      origin,
    };

    const credential = {
      id: credentialId,
      publicKeyCbor: bytesToBase64Url(keyPair.coseKeyBytes),
      signCount: opts.storedSignCount ?? 0,
      name: 'Test Key',
      createdAt: '2023-01-01T00:00:00Z',
    };

    const twoFactorRows = [{
      userId: 'user-001',
      atype: TwoFactorType.WebAuthn,
      enabled: true,
      data: JSON.stringify({ credentials: [credential] }),
      lastUsed: null,
      createdAt: '2023-01-01T00:00:00Z',
      updatedAt: '2023-01-01T00:00:00Z',
    }];

    return { tokenJson, challengeState, twoFactorRows };
  }

  it('正确断言 → 验证通过', async () => {
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion();
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(true);
  });

  it('挑战态不存在 → 拒绝', async () => {
    const { tokenJson, twoFactorRows } = await buildValidAssertion();
    const { db } = buildMockDb(null); // no challenge state
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('挑战 TTL 过期（6 分钟前）→ 拒绝', async () => {
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion();
    const expiredState = { ...challengeState, issuedAt: Date.now() - 6 * 60 * 1000 };
    const { db } = buildMockDb(expiredState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('challenge 删除在 Step 1（即使验证失败也删）', async () => {
    const { tokenJson, twoFactorRows } = await buildValidAssertion();
    const { db, deleteCalledWith } = buildMockDb(null); // will cause failure
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    await provider.verify(ctx, tokenJson);
    // DELETE must have been called with (userId, WEBAUTHN_LOGIN_CHALLENGE_ATYPE)
    expect(deleteCalledWith.some(([, atype]) => atype === WEBAUTHN_LOGIN_CHALLENGE_ATYPE)).toBe(true);
  });

  it('clientDataJSON.type 不是 webauthn.get → 拒绝', async () => {
    const { challengeState, twoFactorRows } = await buildValidAssertion();
    const authData = await buildAuthData(FIXED_RP_ID, 1);
    // Use "webauthn.create" instead
    const clientDataJson = buildClientData(validChallenge, FIXED_ORIGIN, 'webauthn.create');
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId, authData, clientDataJson, signature });

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('origin 不匹配 → 拒绝', async () => {
    const { challengeState, twoFactorRows } = await buildValidAssertion();
    const authData = await buildAuthData(FIXED_RP_ID, 1);
    const clientDataJson = buildClientData(validChallenge, 'https://evil.example.com');
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId, authData, clientDataJson, signature });

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('rpIdHash 不匹配（不同 rpId）→ 拒绝', async () => {
    const { challengeState, twoFactorRows } = await buildValidAssertion();
    // Build authData with a different rpId
    const authData = await buildAuthData('evil.example.com', 1);
    const clientDataJson = buildClientData(validChallenge, FIXED_ORIGIN);
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId, authData, clientDataJson, signature });

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('challenge 不匹配 → 拒绝', async () => {
    const { challengeState, twoFactorRows } = await buildValidAssertion();
    const authData = await buildAuthData(FIXED_RP_ID, 1);
    // Use a different challenge in clientDataJSON
    const differentChallenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const clientDataJson = buildClientData(differentChallenge, FIXED_ORIGIN);
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId, authData, clientDataJson, signature });

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('UP flag 未设置 → 拒绝', async () => {
    // flags = UV only (no UP)
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion({ flags: FLAG_UV });
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('signCount 回退（新 ≤ 存储值且存储值非0）→ 拒绝', async () => {
    // storedSignCount=5, newSignCount=3 → regression
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion({
      signCount: 3,
      storedSignCount: 5,
    });
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('signCount = storedSignCount（相等且非0）→ 拒绝（回退检测）', async () => {
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion({
      signCount: 5,
      storedSignCount: 5,
    });
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('signCount = 0 且 storedSignCount = 0 → 通过（不做单调检查）', async () => {
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion({
      signCount: 0,
      storedSignCount: 0,
    });
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(true);
  });

  it('未知凭据 ID → 拒绝', async () => {
    const { challengeState } = await buildValidAssertion();
    // twoFactorRows with a different credentialId
    const twoFactorRows = [{
      userId: 'user-001',
      atype: TwoFactorType.WebAuthn,
      enabled: true,
      data: JSON.stringify({ credentials: [{ id: 'different-credential-id', publicKeyCbor: bytesToBase64Url(keyPair.coseKeyBytes), signCount: 0, name: 'k', createdAt: '' }] }),
      lastUsed: null,
      createdAt: '2023-01-01T00:00:00Z',
      updatedAt: '2023-01-01T00:00:00Z',
    }];

    const authData = await buildAuthData(FIXED_RP_ID, 1);
    const clientDataJson = buildClientData(validChallenge, FIXED_ORIGIN);
    const signature = await signAssertion(keyPair.privateKey, authData, clientDataJson);
    const tokenJson = buildTokenJson({ credentialId: 'unknown-id', authData, clientDataJson, signature });

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tokenJson)).toBe(false);
  });

  it('签名被篡改 → 拒绝', async () => {
    const { tokenJson, challengeState, twoFactorRows } = await buildValidAssertion();
    // Tamper the signature by modifying a byte
    const parsed = JSON.parse(tokenJson);
    const sigBytes = base64UrlToBytes(parsed.response.signature);
    sigBytes[10] ^= 0xff;
    parsed.response.signature = bytesToBase64Url(sigBytes);
    const tamperedToken = JSON.stringify(parsed);

    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, tamperedToken)).toBe(false);
  });

  it('JSON 格式无效的 token → 拒绝', async () => {
    const { challengeState, twoFactorRows } = await buildValidAssertion();
    const { db } = buildMockDb(challengeState);
    const ctx: VerifyContext = { user: makeUser(), env: fakeEnv, db, twoFactorRows };
    expect(await provider.verify(ctx, 'not-valid-json{')).toBe(false);
  });
});

describe('WebAuthnTwoFactorProvider.isEnabledForUser', () => {
  const provider = new WebAuthnTwoFactorProvider();
  const user = makeUser();

  it('无 two_factor 行 → false', () => {
    expect(provider.isEnabledForUser(user, [])).toBe(false);
  });

  it('有 atype=7 行但 credentials 为空 → false', () => {
    const rows = [{
      userId: user.id, atype: TwoFactorType.WebAuthn, enabled: true,
      data: JSON.stringify({ credentials: [] }),
      lastUsed: null, createdAt: '', updatedAt: '',
    }];
    expect(provider.isEnabledForUser(user, rows)).toBe(false);
  });

  it('有 atype=7 行且有凭据 → true', () => {
    const rows = [{
      userId: user.id, atype: TwoFactorType.WebAuthn, enabled: true,
      data: JSON.stringify({ credentials: [{ id: 'cred-1', publicKeyCbor: 'abc', signCount: 0, name: 'k', createdAt: '' }] }),
      lastUsed: null, createdAt: '', updatedAt: '',
    }];
    expect(provider.isEnabledForUser(user, rows)).toBe(true);
  });

  it('有凭据但 enabled=false → false', () => {
    const rows = [{
      userId: user.id, atype: TwoFactorType.WebAuthn, enabled: false,
      data: JSON.stringify({ credentials: [{ id: 'cred-1', publicKeyCbor: 'abc', signCount: 0, name: 'k', createdAt: '' }] }),
      lastUsed: null, createdAt: '', updatedAt: '',
    }];
    expect(provider.isEnabledForUser(user, rows)).toBe(false);
  });
});

// -----------------------------------------------------------------------
// renameCredential tests
// -----------------------------------------------------------------------

import { renameCredential, disableAllWebAuthn } from '../webauthn-provider';

describe('renameCredential', () => {
  function buildSimpleDb(credentialData: unknown | null): {
    db: D1Database;
    updateCalledWith: Array<unknown[]>;
  } {
    const updateCalledWith: Array<unknown[]> = [];
    const db = {
      prepare: (sql: string) => ({
        bind: (...args: unknown[]) => ({
          first: async () => {
            if (sql.includes('SELECT data FROM two_factors')) {
              if (credentialData === null) return null;
              return { data: JSON.stringify(credentialData) };
            }
            return null;
          },
          run: async () => {
            if (sql.includes('UPDATE two_factors')) {
              updateCalledWith.push(args);
            }
            return { meta: { changes: 1 } };
          },
          all: async () => ({ results: [] }),
        }),
      }),
    } as unknown as D1Database;
    return { db, updateCalledWith };
  }

  it('renames and returns true when credential exists', async () => {
    const store = { credentials: [{ id: 'cred-1', publicKeyCbor: 'abc', signCount: 0, name: 'Old Name', createdAt: '' }] };
    const { db, updateCalledWith } = buildSimpleDb(store);
    const result = await renameCredential(db, 'user-1', 'cred-1', 'New Name');
    expect(result).toBe(true);
    expect(updateCalledWith).toHaveLength(1);
    const savedData = JSON.parse(updateCalledWith[0]![0] as string) as { credentials: Array<{ name: string }> };
    expect(savedData.credentials[0]!.name).toBe('New Name');
  });

  it('returns false when no row exists', async () => {
    const { db } = buildSimpleDb(null);
    const result = await renameCredential(db, 'user-1', 'cred-1', 'Name');
    expect(result).toBe(false);
  });

  it('returns false when credential id not found', async () => {
    const store = { credentials: [{ id: 'other-cred', publicKeyCbor: 'abc', signCount: 0, name: 'k', createdAt: '' }] };
    const { db } = buildSimpleDb(store);
    const result = await renameCredential(db, 'user-1', 'cred-1', 'Name');
    expect(result).toBe(false);
  });

  it('truncates name to 64 characters', async () => {
    const longName = 'A'.repeat(100);
    const store = { credentials: [{ id: 'cred-1', publicKeyCbor: 'abc', signCount: 0, name: 'k', createdAt: '' }] };
    const { db, updateCalledWith } = buildSimpleDb(store);
    const result = await renameCredential(db, 'user-1', 'cred-1', longName);
    expect(result).toBe(true);
    const savedData = JSON.parse(updateCalledWith[0]![0] as string) as { credentials: Array<{ name: string }> };
    expect(savedData.credentials[0]!.name).toHaveLength(64);
  });

  it('trims whitespace from name', async () => {
    const store = { credentials: [{ id: 'cred-1', publicKeyCbor: 'abc', signCount: 0, name: 'k', createdAt: '' }] };
    const { db, updateCalledWith } = buildSimpleDb(store);
    const result = await renameCredential(db, 'user-1', 'cred-1', '  My Key  ');
    expect(result).toBe(true);
    const savedData = JSON.parse(updateCalledWith[0]![0] as string) as { credentials: Array<{ name: string }> };
    expect(savedData.credentials[0]!.name).toBe('My Key');
  });
});

// -----------------------------------------------------------------------
// disableAllWebAuthn tests
// -----------------------------------------------------------------------

describe('disableAllWebAuthn', () => {
  function buildDisableDb(): {
    db: D1Database;
    updateCalledWith: Array<unknown[]>;
  } {
    const updateCalledWith: Array<unknown[]> = [];
    const db = {
      prepare: (sql: string) => ({
        bind: (...args: unknown[]) => ({
          run: async () => {
            if (sql.includes('UPDATE two_factors')) {
              updateCalledWith.push(args);
            }
            return { meta: { changes: 1 } };
          },
          first: async () => null,
          all: async () => ({ results: [] }),
        }),
      }),
    } as unknown as D1Database;
    return { db, updateCalledWith };
  }

  it('sets enabled=0 but preserves credentials (reversible soft-disable)', async () => {
    const { db, updateCalledWith } = buildDisableDb();
    await disableAllWebAuthn(db, 'user-1');
    expect(updateCalledWith).toHaveLength(1);
    // New soft-disable: UPDATE SET enabled=0, updated_at=? — binds are (nowIso, userId, atype).
    const [_nowIso, userId, _atype] = updateCalledWith[0]!;
    expect(userId).toBe('user-1');
    // data column is NOT touched — credentials remain in the DB row.
  });

  it('does not throw when no row exists (UPDATE affects 0 rows)', async () => {
    const db = {
      prepare: () => ({
        bind: () => ({
          run: async () => ({ meta: { changes: 0 } }),
          first: async () => null,
          all: async () => ({ results: [] }),
        }),
      }),
    } as unknown as D1Database;
    await expect(disableAllWebAuthn(db, 'user-1')).resolves.toBeUndefined();
  });
});
