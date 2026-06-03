/**
 * two-factor/webauthn-provider.ts
 *
 * WebAuthn / FIDO2 second-factor provider (TwoFactorType 7).
 *
 * Security implementation strictly follows docs/MFA-SECURITY-CHECKLIST.md §1.
 * All five high-risk pitfalls are addressed:
 *   1. TwoFactorProviders2["7"] uses base64url (no padding) for challenge and credentialId.
 *   2. ECDSA DER → raw r‖s conversion before crypto.subtle.verify.
 *   3. Signed data = authData ‖ SHA-256(clientDataJSON).
 *   4. Challenge is deleted immediately upon retrieval (even on failure).
 *   5. signCount regression → security log + reject.
 *
 * Challenge storage: two_factors table with atype=WEBAUTHN_LOGIN_CHALLENGE_ATYPE (1004).
 * Credential storage: two_factors table with atype=7 (TwoFactorType.WebAuthn).
 * Registration challenge: atype=WEBAUTHN_REG_CHALLENGE_ATYPE (1003).
 */

import type { Env, User } from '../../types';
import type { TwoFactorRow } from '../storage-two-factor-repo';
import type {
  ChallengeContext,
  TwoFactorProvider,
  TwoFactorTypeValue,
  VerifyContext,
} from './types';
import { TwoFactorType } from './types';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  extractRpIdAndOrigin,
  parseCoseKey,
  parseClientDataJSON,
  parseAuthenticatorData,
  randomChallenge,
  timingSafeEqual,
  verifyCoseSignature,
  FLAG_AT,
  FLAG_UP,
} from '../../utils/passkey';
import { safeWriteAuditEvent } from '../audit-events';

// ---------------------------------------------------------------------------
// Internal atype values for challenge state rows
// ---------------------------------------------------------------------------

/** D1 atype for a pending WebAuthn registration challenge. */
export const WEBAUTHN_REG_CHALLENGE_ATYPE = 1003;
/** D1 atype for a pending WebAuthn login challenge. */
export const WEBAUTHN_LOGIN_CHALLENGE_ATYPE = 1004;

/** WebAuthn login challenge TTL in seconds (5 minutes). */
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/** RP name shown to the authenticator during registration. */
const RP_NAME = 'NodeWarden';

// ---------------------------------------------------------------------------
// Data shapes stored in two_factors.data
// ---------------------------------------------------------------------------

/** One registered WebAuthn credential (stored as element of WebAuthnCredentialStore.credentials). */
export interface WebAuthnCredential {
  /** base64url credential ID. */
  id: string;
  /** base64url CBOR-encoded COSE public key (raw bytes from attestedCredentialData). */
  publicKeyCbor: string;
  /** Signature counter — updated after each successful assertion. */
  signCount: number;
  /** Human-readable name set by the user. */
  name: string;
  createdAt: string;
}

/** Shape stored in two_factors.data for atype=7. */
interface WebAuthnCredentialStore {
  credentials: WebAuthnCredential[];
}

/** Shape stored in two_factors.data for atype=1004 (login challenge). */
interface LoginChallengeState {
  /** base64url challenge bytes. */
  challenge: string;
  /** Unix ms timestamp at which the challenge was issued. */
  issuedAt: number;
  /** The rpId in effect when the challenge was issued. */
  rpId: string;
  /** The origin in effect when the challenge was issued. */
  origin: string;
}

/** Shape stored in two_factors.data for atype=1003 (registration challenge). */
export interface RegChallengeState {
  challenge: string;
  issuedAt: number;
  rpId: string;
  origin: string;
}

// ---------------------------------------------------------------------------
// Helper: read credential store for a user
// ---------------------------------------------------------------------------

function parseCredentialStore(row: TwoFactorRow | undefined | null): WebAuthnCredentialStore {
  if (!row) return { credentials: [] };
  try {
    const parsed = JSON.parse(row.data) as Partial<WebAuthnCredentialStore>;
    return { credentials: Array.isArray(parsed.credentials) ? parsed.credentials : [] };
  } catch {
    return { credentials: [] };
  }
}

// ---------------------------------------------------------------------------
// Challenge state helpers — stored in two_factors table
// ---------------------------------------------------------------------------

async function saveLoginChallenge(
  db: D1Database,
  userId: string,
  state: LoginChallengeState
): Promise<void> {
  const now = new Date().toISOString();
  await db.prepare(
    'INSERT INTO two_factors (user_id, atype, enabled, data, last_used, created_at, updated_at) ' +
    'VALUES (?, ?, 1, ?, NULL, ?, ?) ' +
    'ON CONFLICT(user_id, atype) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  )
    .bind(userId, WEBAUTHN_LOGIN_CHALLENGE_ATYPE, JSON.stringify(state), now, now)
    .run();
}

async function popLoginChallenge(
  db: D1Database,
  userId: string
): Promise<LoginChallengeState | null> {
  const row = await db
    .prepare('SELECT data FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(userId, WEBAUTHN_LOGIN_CHALLENGE_ATYPE)
    .first<{ data: string }>();

  // Delete immediately — even if state is missing or expired — preventing replay.
  await db
    .prepare('DELETE FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(userId, WEBAUTHN_LOGIN_CHALLENGE_ATYPE)
    .run();

  if (!row) return null;
  try {
    return JSON.parse(row.data) as LoginChallengeState;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// WebAuthn registration: parse attestation object
// ---------------------------------------------------------------------------

/**
 * Parse a base64url-encoded attestationObject (CBOR).
 * Returns the raw authenticatorData bytes.
 * We accept "none" attestation only — no certificate chain verification.
 */
function parseAttestationObject(attestationObjectBase64Url: string): Uint8Array {
  const bytes = base64UrlToBytes(attestationObjectBase64Url);
  // CBOR map: { "fmt": string, "attStmt": map, "authData": bytes }
  // We only need authData — parse minimally.
  // The CBOR major-type of the outer value must be map (5).
  if ((bytes[0] >> 5) !== 5) throw new Error('attestationObject: not a CBOR map');

  // Walk the CBOR map manually looking for "authData" key (text string).
  let offset = 1;
  const numEntries = bytes[0] & 0x1f;
  // Handle longer map lengths
  let entryCount = numEntries;
  if (numEntries === 24) { entryCount = bytes[1]; offset = 2; }
  else if (numEntries === 25) { entryCount = (bytes[1] << 8) | bytes[2]; offset = 3; }

  for (let i = 0; i < entryCount; i++) {
    // Decode key (text string)
    const keyMajor = (bytes[offset] >> 5) & 0x07;
    if (keyMajor !== 3) throw new Error('attestationObject: expected text key');
    const keyLen = bytes[offset] & 0x1f;
    offset++;
    const keyText = new TextDecoder().decode(bytes.slice(offset, offset + keyLen));
    offset += keyLen;

    // Decode value
    const valMajor = (bytes[offset] >> 5) & 0x07;
    if (keyText === 'authData') {
      if (valMajor !== 2) throw new Error('attestationObject: authData is not a byte string');
      const valAdditional = bytes[offset] & 0x1f;
      offset++;
      let dataLen: number;
      if (valAdditional <= 23) { dataLen = valAdditional; }
      else if (valAdditional === 24) { dataLen = bytes[offset]; offset++; }
      else if (valAdditional === 25) { dataLen = (bytes[offset] << 8) | bytes[offset + 1]; offset += 2; }
      else throw new Error('attestationObject: authData length encoding not supported');
      return bytes.slice(offset, offset + dataLen);
    }

    // Skip this value to advance to the next key
    offset = skipCborValue(bytes, offset);
  }
  throw new Error('attestationObject: authData field not found');
}

/** Skip one CBOR-encoded value, returning the offset after it. */
function skipCborValue(buf: Uint8Array, offset: number): number {
  const first = buf[offset];
  const majorType = (first >> 5) & 0x07;
  const addInfo = first & 0x1f;
  offset++;

  function readLen(): number {
    if (addInfo <= 23) return addInfo;
    if (addInfo === 24) { const l = buf[offset]; offset++; return l; }
    if (addInfo === 25) { const l = (buf[offset] << 8) | buf[offset + 1]; offset += 2; return l; }
    throw new Error('CBOR skip: unsupported length');
  }

  if (majorType === 0 || majorType === 1) return offset; // integers: length already consumed
  if (majorType === 2 || majorType === 3) return offset + readLen();
  if (majorType === 4) {
    const n = readLen();
    for (let i = 0; i < n; i++) offset = skipCborValue(buf, offset);
    return offset;
  }
  if (majorType === 5) {
    const n = readLen();
    for (let i = 0; i < n * 2; i++) offset = skipCborValue(buf, offset);
    return offset;
  }
  throw new Error(`CBOR skip: unsupported major type ${majorType}`);
}

// ---------------------------------------------------------------------------
// Token shape from client (twoFactorToken JSON for provider 7)
// ---------------------------------------------------------------------------

interface AssertionToken {
  id?: string;
  rawId?: string;
  type?: string;
  response?: {
    authenticatorData?: string;
    clientDataJSON?: string;
    clientDataJson?: string; // alias — Vaultwarden uses serde alias
    signature?: string;
    userHandle?: string | null;
  };
}

// ---------------------------------------------------------------------------
// WebAuthnTwoFactorProvider
// ---------------------------------------------------------------------------

export class WebAuthnTwoFactorProvider implements TwoFactorProvider {
  readonly type: TwoFactorTypeValue = TwoFactorType.WebAuthn;

  isAvailable(_env: Env): boolean {
    // WebAuthn has no external dependency — always available.
    return true;
  }

  isEnabledForUser(_user: User, twoFactorRows: TwoFactorRow[]): boolean {
    const row = twoFactorRows.find(r => r.atype === TwoFactorType.WebAuthn);
    if (!row || !row.enabled) return false;
    const store = parseCredentialStore(row);
    return store.credentials.length > 0;
  }

  /**
   * Generate and persist a login challenge, returning the TwoFactorProviders2["7"] object.
   * Challenge is stored in two_factors(atype=1004) with a 5-minute TTL.
   */
  async buildChallenge(ctx: ChallengeContext): Promise<Record<string, unknown>> {
    const { user, db, twoFactorRows } = ctx;

    // Derive rpId and origin from the incoming request URL.
    // If no request is available fall back to localhost (dev/test only).
    const { rpId, origin } = ctx.request
      ? extractRpIdAndOrigin(ctx.request)
      : { rpId: 'localhost', origin: 'http://localhost' };

    const challengeBytes = randomChallenge(32);
    const challengeB64 = bytesToBase64Url(challengeBytes);

    const state: LoginChallengeState = {
      challenge: challengeB64,
      issuedAt: Date.now(),
      rpId,
      origin,
    };
    await saveLoginChallenge(db, user.id, state);

    // Build allowCredentials from stored credentials
    const credRow = twoFactorRows.find(r => r.atype === TwoFactorType.WebAuthn);
    const store = parseCredentialStore(credRow);
    const allowCredentials = store.credentials.map(c => ({
      type: 'public-key',
      id: c.id, // already base64url
    }));

    const rpIdHost = rpId;
    return {
      challenge: challengeB64,
      timeout: 60000,
      rpId: rpIdHost,
      allowCredentials,
      userVerification: 'discouraged',
      extensions: {
        appid: `${origin}/app-id.json`,
        uvm: true,
      },
      status: 'ok',
      errorMessage: '',
    };
  }

  /**
   * Verify a WebAuthn assertion token following checklist §1.2 step order.
   * All 10 steps implemented; challenge is deleted at Step 1 regardless of outcome.
   */
  async verify(ctx: VerifyContext, tokenJson: string): Promise<boolean> {
    const { user, env, db } = ctx;

    // --- Step 1: Pop challenge state (delete-first, preventing replay) ---
    const challengeState = await popLoginChallenge(db, user.id);
    if (!challengeState) return false;

    // TTL check (belt-and-suspenders alongside DB storage)
    if (Date.now() - challengeState.issuedAt > CHALLENGE_TTL_MS) return false;

    // Parse assertion token
    let token: AssertionToken;
    try {
      token = JSON.parse(tokenJson) as AssertionToken;
    } catch {
      return false;
    }

    const rawIdB64 = token.rawId ?? token.id ?? '';
    const clientDataB64 = token.response?.clientDataJSON ?? token.response?.clientDataJson ?? '';
    const authDataB64 = token.response?.authenticatorData ?? '';
    const sigB64 = token.response?.signature ?? '';

    if (!rawIdB64 || !clientDataB64 || !authDataB64 || !sigB64) return false;

    // Decode all binary fields
    const credentialId = base64UrlToBytes(rawIdB64);
    const clientDataJsonBytes = base64UrlToBytes(clientDataB64);
    const authDataBytes = base64UrlToBytes(authDataB64);
    const signatureBytes = base64UrlToBytes(sigB64);

    // --- Step 2: clientDataJSON.type ---
    const clientData = parseClientDataJSON(clientDataB64);
    if (!clientData || clientData.type !== 'webauthn.get') return false;

    // --- Step 3: origin ---
    if (clientData.origin !== challengeState.origin) return false;

    // Parse authenticatorData
    let parsedAuthData: ReturnType<typeof parseAuthenticatorData>;
    try {
      parsedAuthData = parseAuthenticatorData(authDataBytes);
    } catch {
      return false;
    }

    // --- Step 4: rpIdHash ---
    const expectedRpIdHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challengeState.rpId))
    );
    let rpIdMatch = true;
    if (parsedAuthData.rpIdHash.length !== expectedRpIdHash.length) rpIdMatch = false;
    else {
      for (let i = 0; i < expectedRpIdHash.length; i++) {
        if (parsedAuthData.rpIdHash[i] !== expectedRpIdHash[i]) { rpIdMatch = false; break; }
      }
    }
    if (!rpIdMatch) return false;

    // --- Step 5: challenge comparison (constant-time) ---
    const receivedChallenge = base64UrlToBytes(clientData.challenge ?? '');
    const storedChallenge = base64UrlToBytes(challengeState.challenge);
    if (!await timingSafeEqual(receivedChallenge, storedChallenge)) return false;

    // --- Step 6: UP flag ---
    if (!(parsedAuthData.flags & FLAG_UP)) return false;

    // --- Step 7: UV flag — userVerification="discouraged", UV optional ---
    // (no rejection for UV=0)

    // Find the matching credential in the user's store
    const credentialIdB64 = bytesToBase64Url(credentialId);
    const credRow = ctx.twoFactorRows.find(r => r.atype === TwoFactorType.WebAuthn);
    const store = parseCredentialStore(credRow);
    const credential = store.credentials.find(c => c.id === credentialIdB64);
    if (!credential) return false;

    // --- Step 8: signCount regression ---
    const newSignCount = parsedAuthData.signCount;
    if (credential.signCount > 0 && newSignCount <= credential.signCount) {
      // Potential credential clone — log and reject
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'webauthn.assertion.sign_count_regression',
        category: 'security',
        level: 'security',
        targetType: 'webauthn_credential',
        targetId: credentialIdB64,
        metadata: {
          stored: credential.signCount,
          received: newSignCount,
          credentialId: credentialIdB64,
        },
      });
      return false;
    }

    // --- Step 9: signature verification ---
    let sigValid: boolean;
    try {
      const coseKey = parseCoseKey(base64UrlToBytes(credential.publicKeyCbor));
      sigValid = await verifyCoseSignature(coseKey, signatureBytes, authDataBytes, clientDataJsonBytes);
    } catch {
      return false;
    }
    if (!sigValid) return false;

    // --- Step 10: update signCount ---
    credential.signCount = newSignCount;
    const updatedStore: WebAuthnCredentialStore = { credentials: store.credentials };
    const nowIso = new Date().toISOString();
    await db.prepare(
      'UPDATE two_factors SET data = ?, last_used = ?, updated_at = ? WHERE user_id = ? AND atype = ?'
    )
      .bind(JSON.stringify(updatedStore), Date.now(), nowIso, user.id, TwoFactorType.WebAuthn)
      .run();

    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'webauthn.assertion.success',
      category: 'auth',
      level: 'info',
      targetType: 'webauthn_credential',
      targetId: credentialIdB64,
      metadata: { signCount: newSignCount },
    });

    return true;
  }
}

export const webAuthnProvider: TwoFactorProvider = new WebAuthnTwoFactorProvider();

// ---------------------------------------------------------------------------
// Registration helpers (used by accounts.ts endpoints)
// ---------------------------------------------------------------------------

export interface WebAuthnRegistrationOptions {
  challenge: string; // base64url
  rpId: string;
  origin: string;
}

/**
 * Generate a registration challenge, persist it (atype=1003), and return
 * the PublicKeyCredentialCreationOptions JSON for the browser.
 */
export async function generateRegistrationChallenge(
  db: D1Database,
  user: User,
  request: Request,
  existingCredentials: WebAuthnCredential[]
): Promise<Record<string, unknown>> {
  const { rpId, origin } = extractRpIdAndOrigin(request);
  const challengeBytes = randomChallenge(32);
  const challengeB64 = bytesToBase64Url(challengeBytes);

  const state: RegChallengeState = {
    challenge: challengeB64,
    issuedAt: Date.now(),
    rpId,
    origin,
  };
  const nowIso = new Date().toISOString();
  await db.prepare(
    'INSERT INTO two_factors (user_id, atype, enabled, data, last_used, created_at, updated_at) ' +
    'VALUES (?, ?, 1, ?, NULL, ?, ?) ' +
    'ON CONFLICT(user_id, atype) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  )
    .bind(user.id, WEBAUTHN_REG_CHALLENGE_ATYPE, JSON.stringify(state), nowIso, nowIso)
    .run();

  const excludeCredentials = existingCredentials.map(c => ({
    type: 'public-key',
    id: c.id,
  }));

  return {
    rp: { id: rpId, name: RP_NAME },
    user: {
      id: bytesToBase64Url(new TextEncoder().encode(user.id)),
      name: user.email,
      displayName: user.email,
    },
    challenge: challengeB64,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
      { type: 'public-key', alg: -8 },
    ],
    timeout: 60000,
    excludeCredentials,
    authenticatorSelection: { userVerification: 'discouraged' },
    attestation: 'none',
    extensions: null,
    status: 'ok',
    errorMessage: '',
  };
}

interface RegistrationBody {
  id?: string;
  rawId?: string;
  type?: string;
  response?: {
    attestationObject?: string;
    clientDataJSON?: string;
    clientDataJson?: string;
  };
  deviceName?: string;
}

/**
 * Complete WebAuthn registration: validate attestation and persist credential.
 *
 * Returns the credential ID on success, or throws on any validation failure.
 */
export async function completeRegistration(
  db: D1Database,
  user: User,
  body: RegistrationBody,
  env: Env
): Promise<WebAuthnCredential> {
  // Pop registration challenge
  const row = await db
    .prepare('SELECT data FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(user.id, WEBAUTHN_REG_CHALLENGE_ATYPE)
    .first<{ data: string }>();
  await db
    .prepare('DELETE FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(user.id, WEBAUTHN_REG_CHALLENGE_ATYPE)
    .run();

  if (!row) throw new Error('Registration challenge not found or expired');

  let state: RegChallengeState;
  try {
    state = JSON.parse(row.data) as RegChallengeState;
  } catch {
    throw new Error('Invalid registration challenge state');
  }

  if (Date.now() - state.issuedAt > CHALLENGE_TTL_MS) {
    throw new Error('Registration challenge expired');
  }

  const clientDataB64 = body.response?.clientDataJSON ?? body.response?.clientDataJson ?? '';
  const attestationObjectB64 = body.response?.attestationObject ?? '';

  if (!clientDataB64 || !attestationObjectB64) throw new Error('Missing clientDataJSON or attestationObject');

  // Validate clientDataJSON
  const clientData = parseClientDataJSON(clientDataB64);
  if (!clientData || clientData.type !== 'webauthn.create') throw new Error('Invalid ceremony type');
  if (clientData.origin !== state.origin) throw new Error('Origin mismatch');

  // Challenge comparison (constant-time)
  const receivedChallenge = base64UrlToBytes(clientData.challenge ?? '');
  const storedChallenge = base64UrlToBytes(state.challenge);
  if (!await timingSafeEqual(receivedChallenge, storedChallenge)) throw new Error('Challenge mismatch');

  // Parse attestationObject
  const authDataBytes = parseAttestationObject(attestationObjectB64);
  const parsedAuthData = parseAuthenticatorData(authDataBytes);

  // rpIdHash
  const expectedRpIdHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(state.rpId))
  );
  if (parsedAuthData.rpIdHash.length !== expectedRpIdHash.length) throw new Error('rpIdHash mismatch');
  for (let i = 0; i < expectedRpIdHash.length; i++) {
    if (parsedAuthData.rpIdHash[i] !== expectedRpIdHash[i]) throw new Error('rpIdHash mismatch');
  }

  // UP flag
  if (!(parsedAuthData.flags & FLAG_UP)) throw new Error('User Presence flag not set');

  // AT flag — must be set for registration
  if (!(parsedAuthData.flags & FLAG_AT)) throw new Error('Attested Credential Data flag not set');

  const attData = parsedAuthData.attestedCredentialData;
  if (!attData) throw new Error('No attested credential data');

  // Validate COSE key algorithm
  try {
    parseCoseKey(attData.credentialPublicKeyBytes);
  } catch (e) {
    throw new Error(`Unsupported public key: ${e instanceof Error ? e.message : e}`);
  }

  const credentialId = bytesToBase64Url(attData.credentialId);
  const publicKeyCbor = bytesToBase64Url(attData.credentialPublicKeyBytes);
  const deviceName = String(body.deviceName ?? '').trim() || 'Security Key';

  const newCredential: WebAuthnCredential = {
    id: credentialId,
    publicKeyCbor,
    signCount: parsedAuthData.signCount,
    name: deviceName.slice(0, 64),
    createdAt: new Date().toISOString(),
  };

  // Persist to two_factors(atype=7)
  const existingRow = await db
    .prepare('SELECT data FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(user.id, TwoFactorType.WebAuthn)
    .first<{ data: string }>();

  let currentStore: WebAuthnCredentialStore;
  try {
    currentStore = existingRow ? (JSON.parse(existingRow.data) as WebAuthnCredentialStore) : { credentials: [] };
    if (!Array.isArray(currentStore.credentials)) currentStore.credentials = [];
  } catch {
    currentStore = { credentials: [] };
  }

  // Prevent duplicate credentials
  if (currentStore.credentials.some(c => c.id === credentialId)) {
    throw new Error('Credential already registered');
  }

  currentStore.credentials.push(newCredential);
  const nowIso = new Date().toISOString();
  await db.prepare(
    'INSERT INTO two_factors (user_id, atype, enabled, data, last_used, created_at, updated_at) ' +
    'VALUES (?, ?, 1, ?, NULL, ?, ?) ' +
    'ON CONFLICT(user_id, atype) DO UPDATE SET enabled = 1, data = excluded.data, updated_at = excluded.updated_at'
  )
    .bind(user.id, TwoFactorType.WebAuthn, JSON.stringify(currentStore), nowIso, nowIso)
    .run();

  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: 'webauthn.registration.success',
    category: 'security',
    level: 'info',
    targetType: 'webauthn_credential',
    targetId: credentialId,
    metadata: { name: newCredential.name },
  });

  return newCredential;
}

/**
 * List registered WebAuthn credentials for a user.
 */
export function listCredentials(twoFactorRows: TwoFactorRow[]): WebAuthnCredential[] {
  const row = twoFactorRows.find(r => r.atype === TwoFactorType.WebAuthn);
  return parseCredentialStore(row).credentials;
}

/**
 * Delete a specific WebAuthn credential by ID.
 * Returns true if the credential was found and removed.
 */
export async function deleteCredential(
  db: D1Database,
  userId: string,
  credentialId: string
): Promise<boolean> {
  const row = await db
    .prepare('SELECT data FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(userId, TwoFactorType.WebAuthn)
    .first<{ data: string }>();

  if (!row) return false;

  let store: WebAuthnCredentialStore;
  try {
    store = JSON.parse(row.data) as WebAuthnCredentialStore;
    if (!Array.isArray(store.credentials)) return false;
  } catch {
    return false;
  }

  const before = store.credentials.length;
  store.credentials = store.credentials.filter(c => c.id !== credentialId);
  if (store.credentials.length === before) return false;

  const nowIso = new Date().toISOString();
  const stillEnabled = store.credentials.length > 0 ? 1 : 0;
  await db.prepare(
    'UPDATE two_factors SET enabled = ?, data = ?, updated_at = ? WHERE user_id = ? AND atype = ?'
  )
    .bind(stillEnabled, JSON.stringify(store), nowIso, userId, TwoFactorType.WebAuthn)
    .run();

  return true;
}
