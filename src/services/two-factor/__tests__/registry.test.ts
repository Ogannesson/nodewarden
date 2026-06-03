/**
 * 注册表与 TOTP provider 的单元测试。
 * 覆盖 P0 地基的派发逻辑（getAvailableProviders / getProvider / isEnabledForUser）。
 */

import { describe, it, expect } from 'vitest';
import { getAvailableProviders, getProvider } from '../registry';
import { TwoFactorType } from '../types';
import type { User } from '../../../types';
import type { TwoFactorRow } from '../../storage-two-factor-repo';

// 最小 fake Env（TOTP provider 不检查 env 字段）
const fakeEnv = {} as unknown as import('../../../types').Env;

// 空 two_factors 行（TOTP 不使用这个表）
const noRows: TwoFactorRow[] = [];

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-001',
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
    ...overrides,
  };
}

describe('getAvailableProviders', () => {
  it('当前注册表包含 TOTP provider (type=0)', () => {
    const providers = getAvailableProviders(fakeEnv);
    expect(providers.length).toBeGreaterThan(0);
    const types = providers.map(p => p.type);
    expect(types).toContain(TwoFactorType.Authenticator);
  });

  it('所有返回的 provider 都满足 isAvailable(env)=true', () => {
    const providers = getAvailableProviders(fakeEnv);
    for (const p of providers) {
      expect(p.isAvailable(fakeEnv)).toBe(true);
    }
  });
});

describe('getProvider', () => {
  it('type=0 返回 TOTP provider', () => {
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv);
    expect(p).not.toBeNull();
    expect(p!.type).toBe(TwoFactorType.Authenticator);
  });

  it('未注册的 type（如 99）返回 null', () => {
    const p = getProvider(99, fakeEnv);
    expect(p).toBeNull();
  });

  it('WebAuthn(7) 在 P1 阶段已实现，返回非 null provider', () => {
    const p = getProvider(TwoFactorType.WebAuthn, fakeEnv);
    expect(p).not.toBeNull();
    expect(p!.type).toBe(TwoFactorType.WebAuthn);
  });
});

describe('TotpTwoFactorProvider.isEnabledForUser', () => {
  it('totpSecret 为 null → false', () => {
    const user = makeUser({ totpSecret: null });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    expect(p.isEnabledForUser(user, noRows)).toBe(false);
  });

  it('totpSecret 为空字符串 → false', () => {
    const user = makeUser({ totpSecret: '' });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    expect(p.isEnabledForUser(user, noRows)).toBe(false);
  });

  it('totpSecret 为有效 base32 → true', () => {
    const user = makeUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    expect(p.isEnabledForUser(user, noRows)).toBe(true);
  });

  it('totpSecret 只含填充符 = → false', () => {
    const user = makeUser({ totpSecret: '======' });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    expect(p.isEnabledForUser(user, noRows)).toBe(false);
  });
});

describe('TotpTwoFactorProvider.buildChallenge', () => {
  it('返回 null（Authenticator 挑战不携带数据）', async () => {
    const user = makeUser({ totpSecret: 'JBSWY3DPEHPK3PXP' });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    const ctx = { user, env: fakeEnv, db: {} as D1Database, twoFactorRows: noRows };
    const result = await p.buildChallenge(ctx);
    expect(result).toBeNull();
  });
});

describe('TotpTwoFactorProvider.verify', () => {
  const TEST_SECRET = 'JBSWY3DPEHPK3PXP';

  it('正确 token 应通过', async () => {
    const user = makeUser({ totpSecret: TEST_SECRET });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    const validToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));
    const ctx = { user, env: fakeEnv, db: {} as D1Database, twoFactorRows: noRows };
    expect(await p.verify(ctx, validToken)).toBe(true);
  });

  it('错误 token 应被拒绝', async () => {
    const user = makeUser({ totpSecret: TEST_SECRET });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    const ctx = { user, env: fakeEnv, db: {} as D1Database, twoFactorRows: noRows };
    // 000000 与当前时刻有效 token 碰撞概率 1/1000000
    const currToken = await computeHotp(TEST_SECRET, Math.floor(Date.now() / 1000 / 30));
    if (currToken !== '000000') {
      expect(await p.verify(ctx, '000000')).toBe(false);
    }
  });

  it('totpSecret 为 null → 直接返回 false', async () => {
    const user = makeUser({ totpSecret: null });
    const p = getProvider(TwoFactorType.Authenticator, fakeEnv)!;
    const ctx = { user, env: fakeEnv, db: {} as D1Database, twoFactorRows: noRows };
    expect(await p.verify(ctx, '123456')).toBe(false);
  });
});

// -----------------------------------------------------------------------
// 辅助（与 totp.ts 相同算法）
// -----------------------------------------------------------------------

function base32Decode(input: string): Uint8Array | null {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = input.toUpperCase().replace(/[\s\-=]/g, '');
  if (!normalized) return null;
  let bits = 0, value = 0;
  const output: number[] = [];
  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bits -= 8; output.push((value >> bits) & 0xff); }
  }
  return output.length > 0 ? new Uint8Array(output) : null;
}

async function computeHotp(secretBase32: string, counter: number): Promise<string> {
  const secret = base32Decode(secretBase32)!;
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = c & 0xff; c = Math.floor(c / 256); }
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  return (binary % 1_000_000).toString().padStart(6, '0');
}
