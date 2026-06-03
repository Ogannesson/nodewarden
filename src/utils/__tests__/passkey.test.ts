/**
 * passkey.ts 工具函数单元测试
 *
 * 覆盖：
 *   - base64url 编解码往返
 *   - DER → raw ECDSA 签名转换（正常、带前导零）
 *   - CBOR/COSE 公钥解析（ES256 / 未知算法拒绝）
 *   - authenticatorData 解析（flags、signCount、AT bit）
 *   - timingSafeEqual 语义
 *   - verifyCoseSignature 端到端（ES256 真实签名）
 */

import { describe, it, expect } from 'vitest';
import {
  bytesToBase64Url,
  base64UrlToBytes,
  derToRawEcdsaSignature,
  parseAuthenticatorData,
  parseCoseKey,
  timingSafeEqual,
  verifyCoseSignature,
  FLAG_UP,
  FLAG_UV,
  FLAG_AT,
  COSE_ALG_ES256,
  COSE_ALG_RS256,
  COSE_ALG_EDDSA,
} from '../passkey';

// -----------------------------------------------------------------------
// base64url 往返
// -----------------------------------------------------------------------

describe('bytesToBase64Url / base64UrlToBytes', () => {
  it('往返：任意字节不变', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255, 62, 63, 64]);
    const b64 = bytesToBase64Url(original);
    // base64url 不含 + / =
    expect(b64).not.toContain('+');
    expect(b64).not.toContain('/');
    expect(b64).not.toContain('=');
    const decoded = base64UrlToBytes(b64);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it('空数组往返', () => {
    const b64 = bytesToBase64Url(new Uint8Array(0));
    const decoded = base64UrlToBytes(b64);
    expect(decoded.length).toBe(0);
  });

  it('已知向量：hello world', () => {
    const bytes = new TextEncoder().encode('hello world');
    const b64 = bytesToBase64Url(bytes);
    expect(b64).toBe('aGVsbG8gd29ybGQ');
  });
});

// -----------------------------------------------------------------------
// DER → raw ECDSA 转换
// -----------------------------------------------------------------------

describe('derToRawEcdsaSignature', () => {
  it('普通 DER（r 和 s 各 32 字节）正确转换', () => {
    // 构造一个规范 DER：r=32 bytes, s=32 bytes
    const r = new Uint8Array(32).fill(0xaa);
    const s = new Uint8Array(32).fill(0xbb);
    const der = new Uint8Array([
      0x30, 68,      // SEQUENCE, length 68
      0x02, 32, ...r, // INTEGER r
      0x02, 32, ...s, // INTEGER s
    ]);
    const raw = derToRawEcdsaSignature(der);
    expect(raw.length).toBe(64);
    expect(Array.from(raw.slice(0, 32))).toEqual(Array.from(r));
    expect(Array.from(raw.slice(32))).toEqual(Array.from(s));
  });

  it('r 带前导 0x00（符号位）时正确剥离', () => {
    // r 有前导 0x00 + 31 bytes，s 有前导 0x00 + 31 bytes
    const rCore = new Uint8Array(31).fill(0xcc);
    const sCore = new Uint8Array(31).fill(0xdd);
    const der = new Uint8Array([
      0x30, 70,
      0x02, 32, 0x00, ...rCore,
      0x02, 32, 0x00, ...sCore,
    ]);
    const raw = derToRawEcdsaSignature(der);
    expect(raw.length).toBe(64);
    // r should be zero-padded on the left: 1 byte of 0 + 31 bytes of 0xcc
    expect(raw[0]).toBe(0x00);
    expect(raw[1]).toBe(0xcc);
    // s similarly
    expect(raw[32]).toBe(0x00);
    expect(raw[33]).toBe(0xdd);
  });

  it('非 DER（首字节不是 0x30）应抛出', () => {
    expect(() => derToRawEcdsaSignature(new Uint8Array([0x31, 0x00]))).toThrow();
  });
});

// -----------------------------------------------------------------------
// authenticatorData 解析
// -----------------------------------------------------------------------

describe('parseAuthenticatorData', () => {
  function buildAuthData(opts: {
    rpIdHashFill?: number;
    flags?: number;
    signCount?: number;
    extraBytes?: Uint8Array;
  } = {}): Uint8Array {
    const rpIdHash = new Uint8Array(32).fill(opts.rpIdHashFill ?? 0xab);
    const flags = opts.flags ?? FLAG_UP;
    const signCount = opts.signCount ?? 5;
    const buf = new Uint8Array(37 + (opts.extraBytes?.length ?? 0));
    buf.set(rpIdHash, 0);
    buf[32] = flags;
    new DataView(buf.buffer).setUint32(33, signCount, false);
    if (opts.extraBytes) buf.set(opts.extraBytes, 37);
    return buf;
  }

  it('正确解析 rpIdHash、flags、signCount', () => {
    const authData = buildAuthData({ flags: FLAG_UP | FLAG_UV, signCount: 42 });
    const parsed = parseAuthenticatorData(authData);
    expect(Array.from(parsed.rpIdHash)).toEqual(Array.from(new Uint8Array(32).fill(0xab)));
    expect(parsed.flags & FLAG_UP).toBeTruthy();
    expect(parsed.flags & FLAG_UV).toBeTruthy();
    expect(parsed.signCount).toBe(42);
  });

  it('数据太短（< 37 字节）应抛出', () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow();
  });

  it('AT flag 不设置时 attestedCredentialData 为 undefined', () => {
    const authData = buildAuthData({ flags: FLAG_UP });
    const parsed = parseAuthenticatorData(authData);
    expect(parsed.attestedCredentialData).toBeUndefined();
  });
});

// -----------------------------------------------------------------------
// COSE 公钥解析 — 未知算法拒绝
// -----------------------------------------------------------------------

describe('parseCoseKey', () => {
  /**
   * 手工构造一个最小 COSE key CBOR：
   *   { 1: kty, 3: alg, -1: crv_or_n, -2: x, -3: y }
   * 仅用于测试 alg 过滤，不需要真实公钥材料。
   */
  function buildMinimalCborMap(entries: [number, number | Uint8Array][]): Uint8Array {
    const parts: number[] = [];
    // CBOR map header
    parts.push((5 << 5) | entries.length); // map of N entries

    for (const [key, val] of entries) {
      // CBOR integer key
      if (key < 0) {
        const absKey = -(key + 1);
        parts.push((1 << 5) | (absKey <= 23 ? absKey : 24));
        if (absKey > 23) parts.push(absKey);
      } else {
        parts.push((0 << 5) | (key <= 23 ? key : 24));
        if (key > 23) parts.push(key);
      }
      // CBOR value
      if (typeof val === 'number') {
        if (val >= 0) {
          parts.push((0 << 5) | (val <= 23 ? val : 24));
          if (val > 23) parts.push(val);
        } else {
          const absVal = -(val + 1);
          parts.push((1 << 5) | (absVal <= 23 ? absVal : 24));
          if (absVal > 23) parts.push(absVal);
        }
      } else {
        // byte string
        parts.push((2 << 5) | (val.length <= 23 ? val.length : 24));
        if (val.length > 23) parts.push(val.length);
        for (const b of val) parts.push(b);
      }
    }
    return new Uint8Array(parts);
  }

  it('ES256（alg=-7）应被接受', () => {
    const cbor = buildMinimalCborMap([
      [1, 2],            // kty=2 (EC2)
      [3, -7],           // alg=-7 (ES256)
      [-1, -7],          // crv=-7 (P-256)
      [-2, new Uint8Array(32).fill(1)],  // x
      [-3, new Uint8Array(32).fill(2)],  // y
    ]);
    expect(() => parseCoseKey(cbor)).not.toThrow();
    const key = parseCoseKey(cbor);
    expect(key.get(3)).toBe(COSE_ALG_ES256);
  });

  it('未知算法（alg=-99）应被拒绝', () => {
    const cbor = buildMinimalCborMap([
      [1, 2],
      [3, -99],
      [-2, new Uint8Array(32)],
    ]);
    expect(() => parseCoseKey(cbor)).toThrow(/unsupported algorithm/i);
  });

  it('alg=0（未知）应被拒绝', () => {
    const cbor = buildMinimalCborMap([
      [1, 2],
      [3, 0],
    ]);
    expect(() => parseCoseKey(cbor)).toThrow(/unsupported algorithm/i);
  });
});

// -----------------------------------------------------------------------
// timingSafeEqual
// -----------------------------------------------------------------------

describe('timingSafeEqual', () => {
  it('相同数据返回 true', async () => {
    const a = new TextEncoder().encode('secret-value');
    const b = new TextEncoder().encode('secret-value');
    expect(await timingSafeEqual(a, b)).toBe(true);
  });

  it('不同数据返回 false', async () => {
    const a = new TextEncoder().encode('value-a');
    const b = new TextEncoder().encode('value-b');
    expect(await timingSafeEqual(a, b)).toBe(false);
  });

  it('不同长度返回 false', async () => {
    const a = new TextEncoder().encode('short');
    const b = new TextEncoder().encode('longer value');
    expect(await timingSafeEqual(a, b)).toBe(false);
  });

  it('空数组相等', async () => {
    expect(await timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

// -----------------------------------------------------------------------
// verifyCoseSignature — ES256 端到端（使用 crypto.subtle 生成真实签名）
// -----------------------------------------------------------------------

describe('verifyCoseSignature (ES256 end-to-end)', () => {
  /**
   * Generate a real P-256 key pair, build a fake COSE key from the public key,
   * sign some data, and verify via verifyCoseSignature.
   */
  async function makeFakeES256CoseKey(): Promise<{
    keyPair: CryptoKeyPair;
    coseKeyBytes: Uint8Array;
  }> {
    const keyPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    )) as CryptoKeyPair;

    // Export public key as JWK to get x and y coordinates
    const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
    const xBytes = base64UrlToBytes(jwk.x!);
    const yBytes = base64UrlToBytes(jwk.y!);

    // Build COSE key CBOR manually
    // Map: { 1: 2, 3: -7, -1: -7, -2: x(32B), -3: y(32B) }
    // CBOR bytestring of 32 bytes: major_type 2, additional_info 24 (= 0x18), then length byte 32
    const parts: number[] = [];
    parts.push((5 << 5) | 5); // map of 5 entries

    // key=1 (kty), val=2 (EC2)
    parts.push(1, 2);
    // key=3 (alg), val=-7 (ES256): major type 1, additional_info = |(-7)|-1 = 6
    parts.push(3, (1 << 5) | 6); // alg=-7
    // key=-1 (crv), val=-7 (P-256)
    parts.push((1 << 5) | 0, (1 << 5) | 6); // crv=-7
    // key=-2 (x), val=x bytes (32B)
    // key -2: major type 1, additional_info 1 → 0x21
    // bytestring 32B: major type 2, additional_info 24 (1-byte length follows), len=32
    parts.push((1 << 5) | 1); // key=-2
    parts.push((2 << 5) | 24, 32); // bytestring len=32
    for (const b of xBytes) parts.push(b);
    // key=-3 (y), val=y bytes (32B)
    parts.push((1 << 5) | 2); // key=-3
    parts.push((2 << 5) | 24, 32);
    for (const b of yBytes) parts.push(b);

    return { keyPair, coseKeyBytes: new Uint8Array(parts) };
  }

  it('正确签名应验证通过', async () => {
    const { keyPair, coseKeyBytes } = await makeFakeES256CoseKey();

    // Fake authData (37 bytes minimum)
    const authData = new Uint8Array(37);
    authData[32] = FLAG_UP;
    // Fake clientDataJSON
    const clientDataJsonBytes = new TextEncoder().encode(
      JSON.stringify({ type: 'webauthn.get', challenge: 'test', origin: 'https://example.com' })
    );

    // Build signedData: authData ‖ SHA-256(clientDataJSON)
    const hashedClientData = new Uint8Array(
      await crypto.subtle.digest('SHA-256', clientDataJsonBytes)
    );
    const signedData = new Uint8Array(authData.byteLength + hashedClientData.byteLength);
    signedData.set(authData, 0);
    signedData.set(hashedClientData, authData.byteLength);

    // Sign with the private key (produces DER-encoded signature)
    const derSig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, signedData)
    );
    // Note: crypto.subtle.sign for ECDSA returns raw r‖s, NOT DER.
    // We need to encode it as DER to simulate what an authenticator would return.
    const rawSig = derSig; // crypto.subtle produces raw r‖s (64 bytes)
    // Convert raw r‖s → DER to simulate authenticator output
    const derFromRaw = rawToDer(rawSig);

    const coseKey = parseCoseKey(coseKeyBytes);
    const valid = await verifyCoseSignature(coseKey, derFromRaw, authData, clientDataJsonBytes);
    expect(valid).toBe(true);
  });

  it('篡改 authData 后签名验证失败', async () => {
    const { keyPair, coseKeyBytes } = await makeFakeES256CoseKey();

    const authData = new Uint8Array(37);
    authData[32] = FLAG_UP;
    const clientDataJsonBytes = new TextEncoder().encode('{"type":"webauthn.get"}');

    const hashedClientData = new Uint8Array(
      await crypto.subtle.digest('SHA-256', clientDataJsonBytes)
    );
    const signedData = new Uint8Array(authData.byteLength + hashedClientData.byteLength);
    signedData.set(authData, 0);
    signedData.set(hashedClientData, authData.byteLength);

    const rawSig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, signedData)
    );
    const derSig = rawToDer(rawSig);

    // Tamper: flip one byte in authData
    const tamperedAuthData = new Uint8Array(authData);
    tamperedAuthData[0] ^= 0xff;

    const coseKey = parseCoseKey(coseKeyBytes);
    const valid = await verifyCoseSignature(coseKey, derSig, tamperedAuthData, clientDataJsonBytes);
    expect(valid).toBe(false);
  });

  it('重放（修改 clientDataJSON）应验证失败', async () => {
    const { keyPair, coseKeyBytes } = await makeFakeES256CoseKey();

    const authData = new Uint8Array(37);
    authData[32] = FLAG_UP;
    const originalClientData = new TextEncoder().encode('{"type":"webauthn.get","challenge":"orig"}');
    const differentClientData = new TextEncoder().encode('{"type":"webauthn.get","challenge":"replay"}');

    const hashedOriginal = new Uint8Array(
      await crypto.subtle.digest('SHA-256', originalClientData)
    );
    const signedData = new Uint8Array(authData.byteLength + hashedOriginal.byteLength);
    signedData.set(authData, 0);
    signedData.set(hashedOriginal, authData.byteLength);

    const rawSig = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, signedData)
    );
    const derSig = rawToDer(rawSig);

    const coseKey = parseCoseKey(coseKeyBytes);
    // Verify against the *different* clientDataJSON — should fail
    const valid = await verifyCoseSignature(coseKey, derSig, authData, differentClientData);
    expect(valid).toBe(false);
  });
});

// -----------------------------------------------------------------------
// Helper: convert raw r‖s (64 bytes) → ASN.1 DER SEQUENCE
// (inverse of derToRawEcdsaSignature, used to simulate authenticator output)
// -----------------------------------------------------------------------

function rawToDer(raw: Uint8Array): Uint8Array {
  let r = raw.slice(0, 32);
  let s = raw.slice(32, 64);

  // Prepend 0x00 if high bit is set (DER positive integer encoding)
  if (r[0] & 0x80) r = new Uint8Array([0x00, ...r]);
  if (s[0] & 0x80) s = new Uint8Array([0x00, ...s]);

  const totalLen = 2 + r.length + 2 + s.length;
  return new Uint8Array([
    0x30, totalLen,
    0x02, r.length, ...r,
    0x02, s.length, ...s,
  ]);
}
