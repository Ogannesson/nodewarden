// ---------------------------------------------------------------------------
// passkey.ts — WebAuthn / FIDO2 低层工具
//
// 包含：base64url 编解码、随机挑战生成、clientDataJSON 解析、
//       CBOR/COSE 公钥解析、DER→raw ECDSA 签名转换、断言验证。
// 所有函数仅使用 Web Crypto API (crypto.subtle)，兼容 Cloudflare Workers。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Base64url 编解码（无填充，URL 安全）
// ---------------------------------------------------------------------------

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(input: string): Uint8Array {
  const normalized = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/** Generate a random challenge as base64url (no padding). Default 32 bytes. */
export function randomChallenge(size: number = 32): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

/** Generate a random challenge as base64url string. */
export function randomChallengeBase64Url(size: number = 32): string {
  return bytesToBase64Url(randomChallenge(size));
}

// ---------------------------------------------------------------------------
// clientDataJSON parsing
// ---------------------------------------------------------------------------

export interface ParsedClientData {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  [key: string]: unknown;
}

export function parseClientDataJSON(base64Url: string): ParsedClientData | null {
  try {
    const raw = base64UrlToBytes(base64Url);
    const text = new TextDecoder().decode(raw);
    const parsed = JSON.parse(text) as ParsedClientData;
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Constant-time buffer comparison (Workers has no crypto.timingSafeEqual)
// ---------------------------------------------------------------------------

/**
 * Constant-time equality. Returns false on length mismatch.
 *
 * Uses an XOR-accumulation loop (same pattern as utils/totp.ts): every byte is
 * compared and the per-byte differences OR-ed together, so the running time
 * depends only on the (equal) length, never on where a mismatch first occurs.
 * This avoids the per-call generateKey + 4× HMAC WebCrypto operations the previous
 * implementation paid on every comparison — it sits on the Email-OTP / recovery
 * verification hot path. Kept async so existing `await` call sites are unchanged.
 */
export async function timingSafeEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Plain byte-level equality (not timing-safe — only use for non-secret data). */
export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder (subset needed for COSE key maps)
//
// We only need to handle CBOR integers, byte strings, and maps — the
// structure used by COSE EC2/RSA/OKP keys (RFC 9052 §7).  We do NOT need
// a full CBOR implementation.
// ---------------------------------------------------------------------------

type CborValue = number | Uint8Array | Map<number, CborValue> | CborValue[];

function decodeCbor(buf: Uint8Array, offset: number = 0): { value: CborValue; nextOffset: number } {
  const first = buf[offset];
  const majorType = (first >> 5) & 0x07;
  const additionalInfo = first & 0x1f;
  offset++;

  function readLength(addInfo: number): { len: number; offset: number } {
    if (addInfo <= 23) return { len: addInfo, offset };
    if (addInfo === 24) return { len: buf[offset], offset: offset + 1 };
    if (addInfo === 25) return { len: (buf[offset] << 8) | buf[offset + 1], offset: offset + 2 };
    if (addInfo === 26) {
      const l = ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
      return { len: l, offset: offset + 4 };
    }
    throw new Error(`CBOR: unsupported additional info ${addInfo}`);
  }

  // Major type 0: unsigned integer
  if (majorType === 0) {
    const { len, offset: o } = readLength(additionalInfo);
    return { value: len, nextOffset: o };
  }

  // Major type 1: negative integer (–1 – n)
  if (majorType === 1) {
    const { len, offset: o } = readLength(additionalInfo);
    return { value: -1 - len, nextOffset: o };
  }

  // Major type 2: byte string
  if (majorType === 2) {
    const { len, offset: o } = readLength(additionalInfo);
    return { value: buf.slice(o, o + len), nextOffset: o + len };
  }

  // Major type 3: text string — treated same as byte string for COSE keys
  if (majorType === 3) {
    const { len, offset: o } = readLength(additionalInfo);
    return { value: buf.slice(o, o + len), nextOffset: o + len };
  }

  // Major type 4: array
  if (majorType === 4) {
    const { len, offset: o } = readLength(additionalInfo);
    let cur = o;
    const arr: CborValue[] = [];
    for (let i = 0; i < len; i++) {
      const res = decodeCbor(buf, cur);
      arr.push(res.value);
      cur = res.nextOffset;
    }
    return { value: arr, nextOffset: cur };
  }

  // Major type 5: map
  if (majorType === 5) {
    const { len, offset: o } = readLength(additionalInfo);
    let cur = o;
    const map = new Map<number, CborValue>();
    for (let i = 0; i < len; i++) {
      const keyRes = decodeCbor(buf, cur);
      cur = keyRes.nextOffset;
      const valRes = decodeCbor(buf, cur);
      cur = valRes.nextOffset;
      if (typeof keyRes.value === 'number') {
        map.set(keyRes.value, valRes.value);
      }
      // Non-integer keys are ignored (not needed for COSE key maps)
    }
    return { value: map, nextOffset: cur };
  }

  throw new Error(`CBOR: unsupported major type ${majorType}`);
}

// ---------------------------------------------------------------------------
// COSE key parsing (RFC 9052)
// ---------------------------------------------------------------------------

export const COSE_ALG_ES256 = -7;   // ECDSA P-256 + SHA-256
export const COSE_ALG_RS256 = -257; // RSASSA-PKCS1-v1_5 + SHA-256
export const COSE_ALG_EDDSA = -8;   // EdDSA (Ed25519)

const ALLOWED_COSE_ALGS = new Set([COSE_ALG_ES256, COSE_ALG_RS256, COSE_ALG_EDDSA]);

type CoseKeyMap = Map<number, CborValue>;

/**
 * Parse a CBOR-encoded COSE key and return the map.
 * Throws if the key uses an unsupported algorithm.
 */
export function parseCoseKey(cborBytes: Uint8Array): CoseKeyMap {
  const { value } = decodeCbor(cborBytes);
  if (!(value instanceof Map)) throw new Error('COSE: key is not a CBOR map');
  const alg = value.get(3);
  if (typeof alg !== 'number' || !ALLOWED_COSE_ALGS.has(alg)) {
    throw new Error(`COSE: unsupported algorithm ${alg}`);
  }
  return value as CoseKeyMap;
}

/** Import a COSE public key into a CryptoKey for use with crypto.subtle.verify(). */
export async function importCosePublicKey(coseKey: CoseKeyMap): Promise<{ key: CryptoKey; alg: number }> {
  const alg = coseKey.get(3) as number;

  if (alg === COSE_ALG_ES256) {
    // kty=2 (EC2), crv=-7 (P-256), x and y are 32-byte coordinates
    const xBytes = coseKey.get(-2);
    const yBytes = coseKey.get(-3);
    if (!(xBytes instanceof Uint8Array) || !(yBytes instanceof Uint8Array)) {
      throw new Error('COSE ES256: missing x or y coordinate');
    }
    const jwk: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: bytesToBase64Url(xBytes),
      y: bytesToBase64Url(yBytes),
      ext: true,
    };
    const key = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['verify']
    );
    return { key, alg };
  }

  if (alg === COSE_ALG_RS256) {
    // kty=3 (RSA), n=modulus (-1), e=exponent (-2)
    const nBytes = coseKey.get(-1);
    const eBytes = coseKey.get(-2);
    if (!(nBytes instanceof Uint8Array) || !(eBytes instanceof Uint8Array)) {
      throw new Error('COSE RS256: missing n or e');
    }
    const jwk: JsonWebKey = {
      kty: 'RSA',
      n: bytesToBase64Url(nBytes),
      e: bytesToBase64Url(eBytes),
      alg: 'RS256',
      ext: true,
    };
    const key = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
      false, ['verify']
    );
    return { key, alg };
  }

  if (alg === COSE_ALG_EDDSA) {
    // kty=1 (OKP), crv=-8 (Ed25519), x=32-byte public key
    const xBytes = coseKey.get(-2);
    if (!(xBytes instanceof Uint8Array)) throw new Error('COSE EdDSA: missing x (public key bytes)');
    const key = await crypto.subtle.importKey(
      'raw', xBytes,
      { name: 'Ed25519' },
      false, ['verify']
    );
    return { key, alg };
  }

  throw new Error(`COSE: unsupported algorithm ${alg}`);
}

// ---------------------------------------------------------------------------
// ECDSA DER → raw r‖s conversion (required for ES256 with crypto.subtle)
//
// WebAuthn authenticators output ASN.1 DER-encoded ECDSA signatures.
// crypto.subtle.verify({ name: "ECDSA" }) requires raw r‖s (64 bytes for P-256).
// ---------------------------------------------------------------------------

/**
 * Convert an ASN.1 DER-encoded ECDSA signature to raw r‖s format (64 bytes for P-256).
 * Directly transcribed from checklist §1.3.
 */
export function derToRawEcdsaSignature(derSig: Uint8Array): Uint8Array {
  // DER SEQUENCE: 0x30 <totalLen> 0x02 <rLen> <r> 0x02 <sLen> <s>
  if (derSig[0] !== 0x30) throw new Error('ECDSA DER: not a SEQUENCE (byte 0 !== 0x30)');
  let offset = 2; // skip tag + length

  if (derSig[offset] !== 0x02) throw new Error('ECDSA DER: expected INTEGER tag for r');
  const rLen = derSig[offset + 1];
  let r = derSig.slice(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;

  if (derSig[offset] !== 0x02) throw new Error('ECDSA DER: expected INTEGER tag for s');
  const sLen = derSig[offset + 1];
  let s = derSig.slice(offset + 2, offset + 2 + sLen);

  // DER INTEGERs may have a leading 0x00 padding byte (sign bit); strip it.
  if (r[0] === 0x00) r = r.slice(1);
  if (s[0] === 0x00) s = s.slice(1);

  // P-256: r and s are each 32 bytes; left-pad with zeros if shorter.
  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);
  return raw;
}

// ---------------------------------------------------------------------------
// Signature verification dispatch
// ---------------------------------------------------------------------------

/**
 * Verify a WebAuthn assertion signature.
 *
 * signedData = authData ‖ SHA-256(clientDataJSON)
 * signature is as received from the client (DER for ES256, raw for EdDSA/RS256).
 */
export async function verifyCoseSignature(
  coseKey: CoseKeyMap,
  signature: Uint8Array,
  authData: Uint8Array,
  clientDataJsonBytes: Uint8Array
): Promise<boolean> {
  // Build the signed data: authData ‖ SHA-256(clientDataJSON)
  const hashedClientData = new Uint8Array(
    await crypto.subtle.digest('SHA-256', clientDataJsonBytes)
  );
  const signedData = new Uint8Array(authData.byteLength + hashedClientData.byteLength);
  signedData.set(authData, 0);
  signedData.set(hashedClientData, authData.byteLength);

  const { key, alg } = await importCosePublicKey(coseKey);

  if (alg === COSE_ALG_ES256) {
    const rawSig = derToRawEcdsaSignature(signature);
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      key,
      rawSig,
      signedData
    );
  }

  if (alg === COSE_ALG_RS256) {
    // RS256 signature is PKCS#1 v1.5, no conversion needed.
    return crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      signature,
      signedData
    );
  }

  if (alg === COSE_ALG_EDDSA) {
    // EdDSA: no hash param — Ed25519 uses SHA-512 internally.
    return crypto.subtle.verify(
      { name: 'Ed25519' },
      key,
      signature,
      signedData
    );
  }

  throw new Error(`COSE: unsupported algorithm in verifyCoseSignature: ${alg}`);
}

// ---------------------------------------------------------------------------
// authenticatorData layout helpers
// ---------------------------------------------------------------------------

export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;     // bytes 0..31
  flags: number;            // byte 32
  signCount: number;        // bytes 33..36 (uint32 big-endian)
  /** Attested credential data (registration only; present if flags AT bit set). */
  attestedCredentialData?: {
    aaguid: Uint8Array;         // bytes 37..52 (16 bytes)
    credentialId: Uint8Array;   // variable length
    credentialPublicKeyBytes: Uint8Array; // CBOR COSE key bytes
  };
}

export const FLAG_UP = 0x01;  // User Presence
export const FLAG_UV = 0x04;  // User Verification
export const FLAG_AT = 0x40;  // Attested Credential Data present

export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
  if (authData.length < 37) throw new Error('authenticatorData too short (< 37 bytes)');

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0, false);

  const result: ParsedAuthenticatorData = { rpIdHash, flags, signCount };

  if (flags & FLAG_AT) {
    // Attested credential data starts at byte 37
    let offset = 37;
    const aaguid = authData.slice(offset, offset + 16);
    offset += 16;

    const credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
    offset += 2;

    const credentialId = authData.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // The remaining bytes are the CBOR-encoded COSE public key
    const credentialPublicKeyBytes = authData.slice(offset);

    result.attestedCredentialData = { aaguid, credentialId, credentialPublicKeyBytes };
  }

  return result;
}

// ---------------------------------------------------------------------------
// extractRpIdAndOrigin: derive rpId and expected origin from a request URL.
// The server has no explicit DOMAIN config; we trust the incoming Host header
// for WebAuthn rpId construction (consistent with how the Web Vault is served).
// ---------------------------------------------------------------------------

export function extractRpIdAndOrigin(request: Request): { rpId: string; origin: string } {
  const url = new URL(request.url);
  const rpId = url.hostname;
  const origin = `${url.protocol}//${url.host}`;
  return { rpId, origin };
}
