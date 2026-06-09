/**
 * app-reenable-2fa.test.ts — #11 MFA 重新启用（reenable）数据流白盒单测
 *
 * 锁定 auth.ts 中四个 reenable API 函数与 performWebAuthnAssertion 的契约：
 *  - reEnableTotp：PUT 请求体携带 token（活体验证码），缺/错码服务端拒绝时抛可见错误
 *  - getWebAuthnReenableChallenge（phase1）：仅 POST masterPasswordHash，返回 challenge 选项
 *  - reEnableWebAuthn（phase2）：把序列化 assertion 原样作为 token 透传
 *  - reEnableEmailTwoFactor：两阶段——无 token→codeSent+masked email；带 token→验证
 *  - performWebAuthnAssertion：navigator.credentials.get 取消/失败时抛错（不静默吞）
 *
 * 这些都是安全相关路径：每条失败必须给用户可见错误，token/口令绝不能丢失或落日志。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// i18n 的 t / translateServerError：t 回显 key，translateServerError 回退到 fallback。
vi.mock('@/lib/i18n', () => ({
  t: vi.fn((key: string) => key),
  translateServerError: vi.fn((_err: unknown, fallback: string) => fallback),
}));

import {
  reEnableTotp,
  getWebAuthnReenableChallenge,
  reEnableWebAuthn,
  reEnableEmailTwoFactor,
  performWebAuthnAssertion,
} from '@/lib/api/auth';

// -----------------------------------------------------------------------
// 工具：捕获 authedFetch 收到的 (url, init)，并用真实 Response 回放服务端响应
// -----------------------------------------------------------------------

type Capture = { url: string; init?: RequestInit };

function makeAuthedFetch(response: Response) {
  const calls: Capture[] = [];
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return response;
  });
  return { fn, calls };
}

function jsonResponse(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** 解析某次 authedFetch 调用的 JSON body。 */
function bodyOf(calls: Capture[], idx = 0): Record<string, unknown> {
  const raw = calls[idx]?.init?.body;
  return raw ? (JSON.parse(String(raw)) as Record<string, unknown>) : {};
}

const MASTER_HASH = 'master-hash-base64==';

// =======================================================================
// reEnableTotp — token（活体验证码）透传 + 错误冒泡
// =======================================================================

describe('reEnableTotp — TOTP 重启用需活体验证码', () => {
  it('成功路径：PUT /api/accounts/totp，body 含 enabled/masterPasswordHash/token', async () => {
    const { fn, calls } = makeAuthedFetch(jsonResponse({ enabled: true }));
    await reEnableTotp(fn, MASTER_HASH, '123456');

    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls[0].url).toBe('/api/accounts/totp');
    expect(calls[0].init?.method).toBe('PUT');
    const body = bodyOf(calls);
    expect(body.enabled).toBe(true);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
    expect(body.token).toBe('123456'); // 活体码原样透传
  });

  it('错码被拒：服务端 400 → 抛可见错误（不静默）', async () => {
    const { fn } = makeAuthedFetch(
      jsonResponse({ error: 'invalid_token', error_description: 'bad code' }, 400),
    );
    await expect(reEnableTotp(fn, MASTER_HASH, '000000')).rejects.toThrow();
  });

  it('未传 token：body 不含 token 键（JSON.stringify 省略 undefined），服务端据此拒绝', async () => {
    const { fn, calls } = makeAuthedFetch(jsonResponse({ enabled: true }));
    await reEnableTotp(fn, MASTER_HASH);
    const body = bodyOf(calls);
    expect('token' in body).toBe(false);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
  });
});

// =======================================================================
// WebAuthn 两阶段：phase1 取 challenge → phase2 透传 assertion 作 token
// =======================================================================

describe('getWebAuthnReenableChallenge — phase1 仅发 masterPasswordHash', () => {
  it('成功：POST /reenable，body 只含 masterPasswordHash（无 token），返回 challenge 选项', async () => {
    const challenge = {
      challenge: 'Y2hhbGxlbmdl',
      allowCredentials: [{ type: 'public-key', id: 'cred-1' }],
      rpId: 'example.com',
      userVerification: 'discouraged',
      timeout: 60000,
    };
    const { fn, calls } = makeAuthedFetch(jsonResponse(challenge));
    const result = await getWebAuthnReenableChallenge(fn, MASTER_HASH);

    expect(calls[0].url).toBe('/api/two-factor/webauthn/reenable');
    expect(calls[0].init?.method).toBe('POST');
    const body = bodyOf(calls);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
    expect('token' in body).toBe(false); // phase1 绝不带 assertion

    // 返回结构能直接喂给 performWebAuthnAssertion
    expect(result.challenge).toBe('Y2hhbGxlbmdl');
    expect(result.rpId).toBe('example.com');
    expect(result.allowCredentials).toEqual([{ type: 'public-key', id: 'cred-1' }]);
  });

  it('phase1 失败：服务端 400 → 抛可见错误', async () => {
    const { fn } = makeAuthedFetch(jsonResponse({ error: 'invalid_password' }, 400));
    await expect(getWebAuthnReenableChallenge(fn, MASTER_HASH)).rejects.toThrow();
  });

  it('空响应体也安全降级为 {}（不抛异常）', async () => {
    const { fn } = makeAuthedFetch(new Response('', { status: 200 }));
    await expect(getWebAuthnReenableChallenge(fn, MASTER_HASH)).resolves.toEqual({});
  });
});

describe('reEnableWebAuthn — phase2 把 assertionJson 原样作 token 透传', () => {
  it('成功：POST /reenable，body 含 masterPasswordHash + token=assertionJson', async () => {
    const assertionJson = JSON.stringify({ id: 'cred-1', response: { signature: 'sig' } });
    const { fn, calls } = makeAuthedFetch(jsonResponse({ enabled: true, keys: [] }));
    await reEnableWebAuthn(fn, MASTER_HASH, assertionJson);

    expect(calls[0].url).toBe('/api/two-factor/webauthn/reenable');
    const body = bodyOf(calls);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
    // assertion 序列化串原样作为 token 字段——服务端用它对照存留 credential 验签
    expect(body.token).toBe(assertionJson);
  });

  it('phase2 验签失败：服务端 400 → 抛可见错误（不静默吞）', async () => {
    const { fn } = makeAuthedFetch(
      jsonResponse({ error: 'webauthn_failed', error_description: 'verification failed' }, 400),
    );
    await expect(
      reEnableWebAuthn(fn, MASTER_HASH, JSON.stringify({ id: 'x' })),
    ).rejects.toThrow();
  });
});

// =======================================================================
// reEnableEmailTwoFactor — 两阶段 codeSent 分支
// =======================================================================

describe('reEnableEmailTwoFactor — 两阶段发码/验码', () => {
  it('phase1（无 token）：body 只含 masterPasswordHash，返回 codeSent + masked email', async () => {
    const { fn, calls } = makeAuthedFetch(
      jsonResponse({ codeSent: true, email: 't***@example.com' }),
    );
    const result = await reEnableEmailTwoFactor(fn, MASTER_HASH);

    expect(calls[0].url).toBe('/api/two-factor/email/reenable');
    expect(calls[0].init?.method).toBe('POST');
    const body = bodyOf(calls);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
    expect('token' in body).toBe(false); // phase1 不带 token

    expect(result.codeSent).toBe(true);
    expect(result.email).toBe('t***@example.com');
  });

  it('phase1 服务端未回 email：email 归一化为 null（不 undefined）', async () => {
    const { fn } = makeAuthedFetch(jsonResponse({ codeSent: true }));
    const result = await reEnableEmailTwoFactor(fn, MASTER_HASH);
    expect(result.codeSent).toBe(true);
    expect(result.email).toBeNull();
  });

  it('phase2（带 token）：body 含 masterPasswordHash + token', async () => {
    const { fn, calls } = makeAuthedFetch(jsonResponse({ codeSent: false }));
    const result = await reEnableEmailTwoFactor(fn, MASTER_HASH, '654321');

    const body = bodyOf(calls);
    expect(body.masterPasswordHash).toBe(MASTER_HASH);
    expect(body.token).toBe('654321');
    expect(result.codeSent).toBe(false);
  });

  it('phase1/phase2 失败：服务端 400 → 抛可见错误', async () => {
    const { fn } = makeAuthedFetch(jsonResponse({ error: 'invalid_password' }, 400));
    await expect(reEnableEmailTwoFactor(fn, MASTER_HASH)).rejects.toThrow();
  });

  it('codeSent 缺省时归一化为 false（!!body.codeSent）', async () => {
    const { fn } = makeAuthedFetch(jsonResponse({}));
    const result = await reEnableEmailTwoFactor(fn, MASTER_HASH);
    expect(result.codeSent).toBe(false);
  });
});

// =======================================================================
// performWebAuthnAssertion — 取消/失败必须冒泡为可见错误（不静默）
// =======================================================================

describe('performWebAuthnAssertion — navigator.credentials.get 取消/失败冒泡', () => {
  const challenge = {
    challenge: 'Y2hhbGxlbmdl', // "challenge" base64url
    allowCredentials: [],
    rpId: 'example.com',
    userVerification: 'discouraged' as const,
    timeout: 60000,
  };

  const originalNavigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');

  afterEach(() => {
    // 还原 navigator（Node 21+ 内置 navigator 是只读 getter，必须用 defineProperty 还原）
    if (originalNavigatorDescriptor) {
      Object.defineProperty(globalThis, 'navigator', originalNavigatorDescriptor);
    } else {
      delete (globalThis as { navigator?: unknown }).navigator;
    }
    vi.restoreAllMocks();
  });

  function stubNavigatorGet(impl: () => Promise<unknown>) {
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      writable: true,
      value: { credentials: { get: vi.fn(impl) } },
    });
  }

  it('用户取消（NotAllowedError）→ 抛错（txt_webauthn_get_cancelled），不返回空串', async () => {
    stubNavigatorGet(async () => {
      throw new DOMException('user cancelled', 'NotAllowedError');
    });
    await expect(performWebAuthnAssertion(challenge)).rejects.toThrow();
  });

  it('中止（AbortError）→ 抛错，不静默吞掉', async () => {
    stubNavigatorGet(async () => {
      throw new DOMException('aborted', 'AbortError');
    });
    await expect(performWebAuthnAssertion(challenge)).rejects.toThrow();
  });

  it('get 返回 null（无凭据）→ 抛错而非返回脏数据', async () => {
    stubNavigatorGet(async () => null);
    await expect(performWebAuthnAssertion(challenge)).rejects.toThrow();
  });

  it('其它 DOMException（如 SecurityError）→ 同样抛错', async () => {
    stubNavigatorGet(async () => {
      throw new DOMException('bad origin', 'SecurityError');
    });
    await expect(performWebAuthnAssertion(challenge)).rejects.toThrow();
  });
});
