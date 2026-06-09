import { describe, it, expect } from 'vitest';
import { createRecoveryCode, hashRecoveryCode, recoveryCodeEquals } from '../recovery-code';

describe('createRecoveryCode', () => {
  it('生成的恢复码包含 8 段，每段4字符，空格分隔', () => {
    const code = createRecoveryCode();
    const parts = code.split(' ');
    expect(parts).toHaveLength(8);
    for (const part of parts) {
      expect(part).toMatch(/^[A-Z2-7]{4}$/);
    }
  });

  it('去除空格后长度为 32', () => {
    const code = createRecoveryCode();
    expect(code.replace(/ /g, '')).toHaveLength(32);
  });

  it('生成的恢复码只含 base32 字符（A-Z 和 2-7）及空格', () => {
    const code = createRecoveryCode();
    expect(code).toMatch(/^[A-Z2-7 ]+$/);
  });

  it('连续生成两次结果不相同（概率断言，极极低概率失败）', () => {
    const code1 = createRecoveryCode();
    const code2 = createRecoveryCode();
    // 2^160 种可能，碰撞概率约 2^-160，实践中不会发生
    expect(code1).not.toBe(code2);
  });
});

describe('hashRecoveryCode', () => {
  it('同一明文码哈希值相同（确定性）', async () => {
    const code = createRecoveryCode();
    const h1 = await hashRecoveryCode(code);
    const h2 = await hashRecoveryCode(code);
    expect(h1).toBe(h2);
  });

  it('返回 64 字符小写十六进制（SHA-256）', async () => {
    const hash = await hashRecoveryCode(createRecoveryCode());
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('带空格和不带空格的同一码哈希相同（normalise 后计算）', async () => {
    const code = createRecoveryCode();
    const compact = code.replace(/ /g, '');
    expect(await hashRecoveryCode(code)).toBe(await hashRecoveryCode(compact));
  });

  it('不同码产生不同哈希', async () => {
    const h1 = await hashRecoveryCode(createRecoveryCode());
    const h2 = await hashRecoveryCode(createRecoveryCode());
    expect(h1).not.toBe(h2);
  });
});

describe('recoveryCodeEquals – 新哈希格式（stored = 64-char hex）', () => {
  it('H4: 正确码与存储哈希匹配，返回 match:true, 无 upgradedHash', async () => {
    const code = createRecoveryCode();
    const stored = await hashRecoveryCode(code);
    const result = await recoveryCodeEquals(code, stored);
    expect(result.match).toBe(true);
    expect(result.upgradedHash).toBeUndefined();
  });

  it('H4: 错误码与存储哈希不匹配，返回 match:false', async () => {
    const code1 = createRecoveryCode();
    const code2 = createRecoveryCode();
    const stored = await hashRecoveryCode(code1);
    const result = await recoveryCodeEquals(code2, stored);
    expect(result.match).toBe(false);
  });

  it('H4: 忽略空格差异（normalise 后哈希一致）', async () => {
    const code = createRecoveryCode();
    const compact = code.replace(/ /g, '');
    const stored = await hashRecoveryCode(code);
    const result = await recoveryCodeEquals(compact, stored);
    expect(result.match).toBe(true);
  });

  it('H4: 小写输入被接受（normalise 转大写后哈希一致）', async () => {
    const code = createRecoveryCode();
    const stored = await hashRecoveryCode(code);
    const result = await recoveryCodeEquals(code.toLowerCase(), stored);
    expect(result.match).toBe(true);
  });
});

describe('recoveryCodeEquals – 惰性迁移（stored = 旧明文格式）', () => {
  it('H4: 旧明文码匹配时返回 match:true + upgradedHash（升级指令）', async () => {
    const code = createRecoveryCode(); // 旧明文存储格式
    const result = await recoveryCodeEquals(code, code);
    expect(result.match).toBe(true);
    expect(result.upgradedHash).toBeDefined();
    expect(result.upgradedHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('H4: 升级哈希与直接哈希同一明文的结果一致', async () => {
    const code = createRecoveryCode();
    const result = await recoveryCodeEquals(code, code);
    const expectedHash = await hashRecoveryCode(code);
    expect(result.upgradedHash).toBe(expectedHash);
  });

  it('H4: 旧明文码不匹配时返回 match:false', async () => {
    const code1 = createRecoveryCode();
    const code2 = createRecoveryCode();
    const result = await recoveryCodeEquals(code1, code2);
    expect(result.match).toBe(false);
    expect(result.upgradedHash).toBeUndefined();
  });

  it('H4: 带空格的旧明文和不带空格的输入可以匹配', async () => {
    const code = createRecoveryCode();
    const compact = code.replace(/ /g, '');
    const result = await recoveryCodeEquals(compact, code);
    expect(result.match).toBe(true);
    expect(result.upgradedHash).toBeDefined();
  });
});

describe('recoveryCodeEquals – null/undefined/空值', () => {
  it('stored 为 null 返回 match:false', async () => {
    const result = await recoveryCodeEquals('ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567', null);
    expect(result.match).toBe(false);
  });

  it('stored 为 undefined 返回 match:false', async () => {
    const result = await recoveryCodeEquals('ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567', undefined);
    expect(result.match).toBe(false);
  });

  it('空字符串输入返回 match:false', async () => {
    const code = createRecoveryCode();
    const stored = await hashRecoveryCode(code);
    const result = await recoveryCodeEquals('', stored);
    expect(result.match).toBe(false);
  });

  it('常量时间特性：修改一位输入应返回 match:false', async () => {
    const code = createRecoveryCode();
    const stored = await hashRecoveryCode(code);
    const parts = code.split(' ');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const firstChar = parts[0][0];
    const idx = alphabet.indexOf(firstChar);
    const differentChar = alphabet[(idx + 1) % alphabet.length];
    parts[0] = differentChar + parts[0].slice(1);
    const modifiedCode = parts.join(' ');
    const result = await recoveryCodeEquals(modifiedCode, stored);
    expect(result.match).toBe(false);
  });
});
