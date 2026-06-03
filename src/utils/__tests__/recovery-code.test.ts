import { describe, it, expect } from 'vitest';
import { createRecoveryCode, recoveryCodeEquals } from '../recovery-code';

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

describe('recoveryCodeEquals', () => {
  it('相同恢复码（格式一致）返回 true', () => {
    const code = createRecoveryCode();
    expect(recoveryCodeEquals(code, code)).toBe(true);
  });

  it('输入带空格、stored 不带空格：normalize 后相等返回 true', () => {
    const code = createRecoveryCode();
    const compact = code.replace(/ /g, '');
    expect(recoveryCodeEquals(code, compact)).toBe(true);
  });

  it('输入不带空格、stored 带空格：normalize 后相等返回 true', () => {
    const code = createRecoveryCode();
    const compact = code.replace(/ /g, '');
    expect(recoveryCodeEquals(compact, code)).toBe(true);
  });

  it('小写输入应被接受（normalize 转大写）', () => {
    const code = createRecoveryCode();
    expect(recoveryCodeEquals(code.toLowerCase(), code)).toBe(true);
  });

  it('错误恢复码返回 false', () => {
    const code1 = createRecoveryCode();
    const code2 = createRecoveryCode();
    // 极低概率两码相同，但实践中不会发生
    if (code1 !== code2) {
      expect(recoveryCodeEquals(code1, code2)).toBe(false);
    }
  });

  it('stored 为 null 返回 false', () => {
    expect(recoveryCodeEquals('ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567', null)).toBe(false);
  });

  it('stored 为 undefined 返回 false', () => {
    expect(recoveryCodeEquals('ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567', undefined)).toBe(false);
  });

  it('空字符串 vs 空字符串：normalize 后均空，长度不等（0 vs storedNormalized 长度）应返回 false', () => {
    // 空输入 normalize 后长度 0，与任何真正的恢复码长度不同
    const code = createRecoveryCode();
    expect(recoveryCodeEquals('', code)).toBe(false);
  });

  it('常量时间比较不短路：对每对输入行为一致（通过输出验证，不是时序）', () => {
    const code = createRecoveryCode();
    // 修改第一个字符来产生不同的码
    const parts = code.split(' ');
    const firstChar = parts[0][0];
    // 把第一个字符换成不同字符（循环到下一个 base32 字符）
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const idx = alphabet.indexOf(firstChar);
    const differentChar = alphabet[(idx + 1) % alphabet.length];
    parts[0] = differentChar + parts[0].slice(1);
    const modifiedCode = parts.join(' ');
    expect(recoveryCodeEquals(modifiedCode, code)).toBe(false);
  });
});
