/**
 * email-sender.test.ts
 *
 * 单元测试：可插拔 Email 发送层
 *
 * 测试范围：
 *   - HttpEmailSender（fetch mock）
 *   - CloudflareEmailSender（binding mock）
 *   - RetryingEmailSender（重试逻辑）
 *   - FallbackEmailSender（兜底逻辑）
 *   - parseJsonEnv（JSON 解析辅助）
 *   - isEmailSenderConfigured（可用性谓词）
 *   - buildEmailSenderFromEnv（工厂函数）
 *
 * 安全断言：secret / 认证 token 不出现在抛出的错误信息里。
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  HttpEmailSender,
  CloudflareEmailSender,
  RetryingEmailSender,
  FallbackEmailSender,
  parseJsonEnv,
  isEmailSenderConfigured,
  buildEmailSenderFromEnv,
  type EmailMessage,
  type HttpEmailConfig,
} from '../email-sender';
import type { CfEmailBinding } from '../../types';

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof fetch>();
vi.stubGlobal('fetch', mockFetch);

const sampleMessage: EmailMessage = {
  to: 'recipient@example.com',
  subject: 'Test Subject',
  text: 'Hello from test',
};

const sampleMessageWithHtml: EmailMessage = {
  ...sampleMessage,
  html: '<p>Hello from test</p>',
};

// ---------------------------------------------------------------------------
// HttpEmailSender
// ---------------------------------------------------------------------------

describe('HttpEmailSender', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeConfig(overrides: Partial<HttpEmailConfig> = {}): HttpEmailConfig {
    return {
      endpoint: 'https://api.example.com/send',
      from: 'sender@example.com',
      ...overrides,
    };
  }

  it('sends with default field names when no fieldMap provided', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig());
    await sender.send(sampleMessage);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://api.example.com/send');
    expect((init as RequestInit).method).toBe('POST');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.from).toBe('sender@example.com');
    expect(body.to).toBe('recipient@example.com');
    expect(body.subject).toBe('Test Subject');
    expect(body.text).toBe('Hello from test');
    expect(body.html).toBeUndefined(); // no html field when not provided
  });

  it('wraps "to" in array when toAsArray=true', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig({ toAsArray: true }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body.to)).toBe(true);
    expect(body.to).toEqual(['recipient@example.com']);
  });

  it('remaps field names via fieldMap', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig({
      fieldMap: { from: 'sender', to: 'recipient', subject: 'title', text: 'content', html: 'bodyHtml' },
    }));
    await sender.send(sampleMessageWithHtml);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.sender).toBe('sender@example.com');
    expect(body.recipient).toBe('recipient@example.com');
    expect(body.title).toBe('Test Subject');
    expect(body.content).toBe('Hello from test');
    expect(body.bodyHtml).toBe('<p>Hello from test</p>');
    // original keys must not be present
    expect(body.from).toBeUndefined();
    expect(body.to).toBeUndefined();
  });

  it('merges extraBody static fields (extraBody keys appear first, then standard fields)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig({
      extraBody: { apiKey: 'static-key', version: 2 },
    }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.apiKey).toBe('static-key');
    expect(body.version).toBe(2);
    expect(body.from).toBe('sender@example.com'); // standard fields still present
  });

  it('includes html field when message has html', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig());
    await sender.send(sampleMessageWithHtml);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.html).toBe('<p>Hello from test</p>');
  });

  it('does not include html field when message has no html', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig());
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body).not.toHaveProperty('html');
  });

  it('succeeds on any 2xx status code', async () => {
    // Note: 204 No Content cannot have a body in the Fetch API spec; skip it in this loop.
    for (const status of [200, 201, 202]) {
      mockFetch.mockResolvedValueOnce(new Response('', { status }));
      const sender = new HttpEmailSender(makeConfig());
      await expect(sender.send(sampleMessage)).resolves.toBeUndefined();
    }
  });

  it('succeeds on 204 No Content (no body)', async () => {
    // 204 must be constructed without a body per spec.
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const sender = new HttpEmailSender(makeConfig());
    await expect(sender.send(sampleMessage)).resolves.toBeUndefined();
  });

  it('throws with HTTP status and detail on non-2xx response (JSON detail)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{"message":"Rate limit exceeded"}', { status: 429 }));
    const sender = new HttpEmailSender(makeConfig());
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send failed (HTTP 429): Rate limit exceeded');
  });

  it('throws with HTTP status and error field on non-2xx response (error field fallback)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{"error":"Unauthorized"}', { status: 401 }));
    const sender = new HttpEmailSender(makeConfig());
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send failed (HTTP 401): Unauthorized');
  });

  it('throws with HTTP status on non-2xx when body is not JSON', async () => {
    mockFetch.mockResolvedValueOnce(new Response('Not Found', { status: 404, statusText: 'Not Found' }));
    const sender = new HttpEmailSender(makeConfig());
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send failed (HTTP 404)');
  });

  it('throws network error with prefix on fetch rejection', async () => {
    mockFetch.mockRejectedValueOnce(new Error('Network unreachable'));
    const sender = new HttpEmailSender(makeConfig());
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send network error: Network unreachable');
  });

  it('respects custom successStatuses', async () => {
    // status 202 normally is 2xx success, but with successStatuses=[200] only, it should fail
    mockFetch.mockResolvedValueOnce(new Response('{"message":"Accepted but not success"}', { status: 202 }));
    const sender = new HttpEmailSender(makeConfig({ successStatuses: [200] }));
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send failed (HTTP 202)');
  });

  it('succeeds on custom successStatuses including non-2xx', async () => {
    // allow 201 explicitly
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 201 }));
    const sender = new HttpEmailSender(makeConfig({ successStatuses: [200, 201] }));
    await expect(sender.send(sampleMessage)).resolves.toBeUndefined();
  });

  it('merges custom headers with Content-Type, injecting Authorization from config', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig({
      headers: { 'X-Custom': 'custom-value', Authorization: 'Bearer my-secret-token' },
    }));
    await sender.send(sampleMessage);

    const init = mockFetch.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Custom']).toBe('custom-value');
    expect(headers['Authorization']).toBe('Bearer my-secret-token');
  });

  it('does NOT include secret/auth tokens in thrown error message', async () => {
    const SECRET = 'super-secret-api-key-must-not-leak';
    mockFetch.mockResolvedValueOnce(new Response('{"message":"fail"}', { status: 500 }));
    const sender = new HttpEmailSender(makeConfig({
      headers: { Authorization: SECRET },
    }));
    let errorMessage = '';
    try {
      await sender.send(sampleMessage);
    } catch (err) {
      errorMessage = (err as Error).message;
    }
    expect(errorMessage).not.toContain(SECRET);
    expect(errorMessage).toMatch(/Email send failed \(HTTP 500\)/);
  });

  it('does NOT include secret in network error message', async () => {
    const SECRET = 'secret-auth-token-must-not-appear';
    mockFetch.mockRejectedValueOnce(new TypeError('DNS resolution failed'));
    const sender = new HttpEmailSender(makeConfig({
      headers: { Authorization: `Bearer ${SECRET}` },
    }));
    let errorMessage = '';
    try {
      await sender.send(sampleMessage);
    } catch (err) {
      errorMessage = (err as Error).message;
    }
    expect(errorMessage).not.toContain(SECRET);
    expect(errorMessage).toMatch(/Email send network error/);
  });
});

// ---------------------------------------------------------------------------
// HttpEmailSender — 模板模式（bodyTemplate）
// ---------------------------------------------------------------------------

describe('HttpEmailSender bodyTemplate mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeConfig(overrides: Partial<HttpEmailConfig> = {}): HttpEmailConfig {
    return {
      endpoint: 'https://api.example.com/send',
      from: 'sender@example.com',
      ...overrides,
    };
  }

  // --- 嵌套结构：from 作为嵌套对象 ---
  it('replaces nested from object: { from: { email: "{{from}}" } }', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: { email: '{{from}}' },
      to: '{{to}}',
      subject: '{{subject}}',
      text: '{{text}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.from).toEqual({ email: 'sender@example.com' });
    expect(body.to).toBe('recipient@example.com');
    expect(body.subject).toBe('Test Subject');
    expect(body.text).toBe('Hello from test');
  });

  // --- 收件人作为对象数组：recipients:[{ email: "{{to}}" }] ---
  it('replaces placeholder inside recipient object array: recipients: [{ email: "{{to}}" }]', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: { email: '{{from}}' },
      recipients: [{ email: '{{to}}', type: 'to' }],
      subject: '{{subject}}',
      text_content: '{{text}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.recipients).toEqual([{ email: 'recipient@example.com', type: 'to' }]);
    expect(body.from).toEqual({ email: 'sender@example.com' });
  });

  // --- 异名字段：text_content / html_content ---
  it('replaces text_content and html_content (renamed fields) correctly', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: { email: '{{from}}' },
      recipients: [{ email: '{{to}}' }],
      subject: '{{subject}}',
      text_content: '{{text}}',
      html_content: '{{html}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessageWithHtml);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.text_content).toBe('Hello from test');
    expect(body.html_content).toBe('<p>Hello from test</p>');
  });

  // --- 静态字段原样保留 ---
  it('preserves static (non-placeholder) fields unchanged', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      sandbox: true,
      api_version: 2,
      metadata: { source: 'nodewarden' },
      from: { email: '{{from}}' },
      to: '{{to}}',
      subject: '{{subject}}',
      text: '{{text}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.sandbox).toBe(true);
    expect(body.api_version).toBe(2);
    expect(body.metadata).toEqual({ source: 'nodewarden' });
  });

  // --- html undefined → html_content 字段被删除 ---
  it('removes html_content key entirely when message.html is undefined', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: { email: '{{from}}' },
      recipients: [{ email: '{{to}}' }],
      subject: '{{subject}}',
      text_content: '{{text}}',
      html_content: '{{html}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    // sampleMessage has no html
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body).not.toHaveProperty('html_content');
    expect(body.text_content).toBe('Hello from test');
  });

  // --- html undefined → 数组内的 {{html}} 元素被过滤掉 ---
  it('filters out {{html}} placeholder element from array when html is undefined', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      to: '{{to}}',
      parts: ['{{text}}', '{{html}}'],
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    // 只剩 text 对应的元素，html 对应的已被过滤
    expect(body.parts).toEqual(['Hello from test']);
  });

  // --- 注入安全：to 字段含 JSON 特殊字符不破坏结构 ---
  it('injection safety: to field with JSON-special chars does not break body structure', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: { email: '{{from}}' },
      to: '{{to}}',
      subject: '{{subject}}',
      text: '{{text}}',
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    // 恶意 to 值，若用字符串拼接会破坏 JSON
    const maliciousMessage: EmailMessage = {
      to: 'a","x":"y',
      subject: 'Injection Test',
      text: 'Test body',
    };
    await sender.send(maliciousMessage);

    // 重新解析，确认结构完好（不会有额外的 "x" 键）
    const rawBody = (mockFetch.mock.calls[0][1] as RequestInit).body as string;
    const body = JSON.parse(rawBody); // 能解析说明 JSON 结构完好
    expect(body.to).toBe('a","x":"y'); // 作为 JSON 字符串字面量保存
    expect(body).not.toHaveProperty('x'); // 没有注入成功的额外键
    expect(body.from).toEqual({ email: 'sender@example.com' }); // 其它字段完好
  });

  // --- 整值匹配：内嵌占位符（"Hi {{to}}"）不整体替换 ---
  it('does not replace embedded/partial placeholder "Hi {{to}}" — whole-value match only', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      to: '{{to}}',                       // 整值 → 替换
      greeting: 'Hi {{to}}',             // 内嵌 → 不替换（原样保留）
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.to).toBe('recipient@example.com');          // 整值匹配 → 替换成功
    expect(body.greeting).toBe('Hi {{to}}');               // 内嵌 → 不替换
  });

  // --- 向后兼容：无模板时仍走扁平模式 ---
  it('backward compatibility: without bodyTemplate, falls back to flat mode', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const sender = new HttpEmailSender(makeConfig()); // 无 bodyTemplate
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    // 扁平模式：顶层标准字段
    expect(body.from).toBe('sender@example.com');
    expect(body.to).toBe('recipient@example.com');
    expect(body.subject).toBe('Test Subject');
    expect(body.text).toBe('Hello from test');
  });

  // --- 模板模式下 fieldMap/toAsArray/extraBody 被忽略 ---
  it('template mode ignores flat-mode options (fieldMap, toAsArray, extraBody)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from: '{{from}}',
      to: '{{to}}',
      subject: '{{subject}}',
      text: '{{text}}',
    };
    const sender = new HttpEmailSender(makeConfig({
      bodyTemplate: template,
      fieldMap: { from: 'renamed_from', to: 'renamed_to' },
      toAsArray: true,
      extraBody: { extra_key: 'extra_value' },
    }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    // 模板模式：按模板 key 命名，扁平模式的 rename 不生效
    expect(body.from).toBe('sender@example.com');
    expect(body.to).toBe('recipient@example.com'); // 不应是数组
    expect(Array.isArray(body.to)).toBe(false);
    // extraBody 的 extra_key 不出现
    expect(body).not.toHaveProperty('extra_key');
    // renamed_from 不出现
    expect(body).not.toHaveProperty('renamed_from');
  });

  // --- 复杂嵌套：多层对象 + 数组混合 ---
  it('handles deeply nested template with arrays and objects', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      message: {
        from: { email: '{{from}}' },
        to: [{ email: '{{to}}' }],
        content: {
          subject: '{{subject}}',
          text: '{{text}}',
          html: '{{html}}',
        },
      },
      sandbox: true,
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessageWithHtml);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.message.from).toEqual({ email: 'sender@example.com' });
    expect(body.message.to).toEqual([{ email: 'recipient@example.com' }]);
    expect(body.message.content.subject).toBe('Test Subject');
    expect(body.message.content.text).toBe('Hello from test');
    expect(body.message.content.html).toBe('<p>Hello from test</p>');
    expect(body.sandbox).toBe(true);
  });

  // --- 顶层为数组的合法模板正常工作 ---
  it('array-root template: top-level array is traversed and placeholders replaced', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    // 某些 API 接受顶层数组 body
    const template = [
      { email: '{{from}}', role: 'sender' },
      { email: '{{to}}',   role: 'recipient' },
      { subject: '{{subject}}', text: '{{text}}' },
    ];
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body)).toBe(true);
    expect(body[0]).toEqual({ email: 'sender@example.com',    role: 'sender' });
    expect(body[1]).toEqual({ email: 'recipient@example.com', role: 'recipient' });
    expect(body[2]).toEqual({ subject: 'Test Subject', text: 'Hello from test' });
  });

  // --- 顶层数组：html undefined → {{html}} 元素被过滤 ---
  it('array-root template: {{html}} element filtered out when html is undefined', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = ['{{text}}', '{{html}}'];
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body).toEqual(['Hello from test']);
  });

  // --- 复杂嵌套：html undefined 时内嵌 html 字段被删除 ---
  it('removes deeply nested html key when html is undefined', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      message: {
        from: { email: '{{from}}' },
        to: [{ email: '{{to}}' }],
        content: {
          subject: '{{subject}}',
          text: '{{text}}',
          html: '{{html}}',
        },
      },
    };
    const sender = new HttpEmailSender(makeConfig({ bodyTemplate: template }));
    await sender.send(sampleMessage); // sampleMessage 没有 html

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.message.content).not.toHaveProperty('html');
    expect(body.message.content.text).toBe('Hello from test');
  });
});

// ---------------------------------------------------------------------------
// CloudflareEmailSender
// ---------------------------------------------------------------------------

describe('CloudflareEmailSender', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeMockBinding(impl?: Partial<CfEmailBinding>): CfEmailBinding {
    return {
      send: vi.fn().mockResolvedValue({ messageId: 'cf-msg-001' }),
      ...impl,
    };
  }

  it('calls binding.send with correct shape', async () => {
    const binding = makeMockBinding();
    const sender = new CloudflareEmailSender(binding, 'noreply@example.com');
    await sender.send(sampleMessage);

    expect(binding.send).toHaveBeenCalledOnce();
    expect(binding.send).toHaveBeenCalledWith({
      from: 'noreply@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Hello from test',
    });
  });

  it('includes html field in binding call when message has html', async () => {
    const binding = makeMockBinding();
    const sender = new CloudflareEmailSender(binding, 'noreply@example.com');
    await sender.send(sampleMessageWithHtml);

    expect(binding.send).toHaveBeenCalledWith(expect.objectContaining({
      html: '<p>Hello from test</p>',
    }));
  });

  it('does not include html field when message has no html', async () => {
    const binding = makeMockBinding();
    const sender = new CloudflareEmailSender(binding, 'noreply@example.com');
    await sender.send(sampleMessage);

    const callArg = (binding.send as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(callArg).not.toHaveProperty('html');
  });

  it('rethrows binding error with Cloudflare prefix', async () => {
    const binding = makeMockBinding({
      send: vi.fn().mockRejectedValue(new Error('CF binding failure')),
    });
    const sender = new CloudflareEmailSender(binding, 'noreply@example.com');
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send error (Cloudflare): CF binding failure');
  });

  it('wraps non-Error binding throws with Cloudflare prefix', async () => {
    const binding = makeMockBinding({
      send: vi.fn().mockRejectedValue('string error'),
    });
    const sender = new CloudflareEmailSender(binding, 'noreply@example.com');
    await expect(sender.send(sampleMessage)).rejects.toThrow('Email send error (Cloudflare): string error');
  });
});

// ---------------------------------------------------------------------------
// RetryingEmailSender
// ---------------------------------------------------------------------------

describe('RetryingEmailSender', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('succeeds on first attempt without retrying', async () => {
    const inner = { send: vi.fn().mockResolvedValueOnce(undefined) };
    const sender = new RetryingEmailSender(inner);
    await sender.send(sampleMessage);
    expect(inner.send).toHaveBeenCalledOnce();
  });

  it('retries after first failure and succeeds on second attempt (maxAttempts=2)', async () => {
    const inner = {
      send: vi.fn()
        .mockRejectedValueOnce(new Error('Transient error'))
        .mockResolvedValueOnce(undefined),
    };
    const sender = new RetryingEmailSender(inner, 2);
    await sender.send(sampleMessage);
    expect(inner.send).toHaveBeenCalledTimes(2);
  });

  it('throws last error after all attempts fail (maxAttempts=2)', async () => {
    const inner = {
      send: vi.fn()
        .mockRejectedValueOnce(new Error('First failure'))
        .mockRejectedValueOnce(new Error('Second failure')),
    };
    const sender = new RetryingEmailSender(inner, 2);
    await expect(sender.send(sampleMessage)).rejects.toThrow('Second failure');
    expect(inner.send).toHaveBeenCalledTimes(2);
  });

  it('does not exceed maxAttempts (3 failures, maxAttempts=2)', async () => {
    const inner = {
      send: vi.fn()
        .mockRejectedValue(new Error('Always fails')),
    };
    const sender = new RetryingEmailSender(inner, 2);
    await expect(sender.send(sampleMessage)).rejects.toThrow('Always fails');
    // Must only attempt exactly 2 times
    expect(inner.send).toHaveBeenCalledTimes(2);
  });

  it('uses default maxAttempts=2', async () => {
    const inner = {
      send: vi.fn().mockRejectedValue(new Error('Always fails')),
    };
    const sender = new RetryingEmailSender(inner); // default
    await expect(sender.send(sampleMessage)).rejects.toThrow();
    expect(inner.send).toHaveBeenCalledTimes(2);
  });

  it('succeeds with 3 attempts configured when third attempt succeeds', async () => {
    const inner = {
      send: vi.fn()
        .mockRejectedValueOnce(new Error('First'))
        .mockRejectedValueOnce(new Error('Second'))
        .mockResolvedValueOnce(undefined),
    };
    const sender = new RetryingEmailSender(inner, 3);
    await sender.send(sampleMessage);
    expect(inner.send).toHaveBeenCalledTimes(3);
  });
});

// ---------------------------------------------------------------------------
// FallbackEmailSender
// ---------------------------------------------------------------------------

describe('FallbackEmailSender', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws immediately on empty senders array', () => {
    expect(() => new FallbackEmailSender([])).toThrow('FallbackEmailSender: senders list must not be empty');
  });

  it('succeeds with first sender without calling second', async () => {
    const first = { send: vi.fn().mockResolvedValueOnce(undefined) };
    const second = { send: vi.fn() };
    const sender = new FallbackEmailSender([first, second]);
    await sender.send(sampleMessage);
    expect(first.send).toHaveBeenCalledOnce();
    expect(second.send).not.toHaveBeenCalled();
  });

  it('falls back to second sender when first fails', async () => {
    const first = { send: vi.fn().mockRejectedValueOnce(new Error('First backend down')) };
    const second = { send: vi.fn().mockResolvedValueOnce(undefined) };
    const sender = new FallbackEmailSender([first, second]);
    await sender.send(sampleMessage);
    expect(first.send).toHaveBeenCalledOnce();
    expect(second.send).toHaveBeenCalledOnce();
  });

  it('throws last error when all senders fail', async () => {
    const first = { send: vi.fn().mockRejectedValueOnce(new Error('First failed')) };
    const second = { send: vi.fn().mockRejectedValueOnce(new Error('Second failed')) };
    const sender = new FallbackEmailSender([first, second]);
    await expect(sender.send(sampleMessage)).rejects.toThrow('Second failed');
  });

  it('throws last error when all three senders fail', async () => {
    const first = { send: vi.fn().mockRejectedValueOnce(new Error('A')) };
    const second = { send: vi.fn().mockRejectedValueOnce(new Error('B')) };
    const third = { send: vi.fn().mockRejectedValueOnce(new Error('C')) };
    const sender = new FallbackEmailSender([first, second, third]);
    await expect(sender.send(sampleMessage)).rejects.toThrow('C');
    expect(first.send).toHaveBeenCalledOnce();
    expect(second.send).toHaveBeenCalledOnce();
    expect(third.send).toHaveBeenCalledOnce();
  });

  it('works with single sender in list', async () => {
    const only = { send: vi.fn().mockResolvedValueOnce(undefined) };
    const sender = new FallbackEmailSender([only]);
    await sender.send(sampleMessage);
    expect(only.send).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// parseJsonEnv
// ---------------------------------------------------------------------------

describe('parseJsonEnv', () => {
  it('returns {} when raw is undefined', () => {
    expect(parseJsonEnv(undefined, 'MY_VAR')).toEqual({});
  });

  it('returns {} when raw is empty string', () => {
    expect(parseJsonEnv('', 'MY_VAR')).toEqual({});
  });

  it('returns {} when raw is whitespace only', () => {
    expect(parseJsonEnv('   ', 'MY_VAR')).toEqual({});
  });

  it('parses valid JSON object', () => {
    expect(parseJsonEnv('{"key":"value","num":42}', 'MY_VAR')).toEqual({ key: 'value', num: 42 });
  });

  it('throws with variable name on invalid JSON', () => {
    expect(() => parseJsonEnv('not valid json{', 'MFA_EMAIL_HTTP_HEADERS'))
      .toThrow('MFA_EMAIL_HTTP_HEADERS: invalid JSON');
  });

  it('throws with variable name when JSON is an array', () => {
    expect(() => parseJsonEnv('[1, 2, 3]', 'MFA_EMAIL_HTTP_BODY'))
      .toThrow('MFA_EMAIL_HTTP_BODY: invalid JSON');
  });

  it('throws with variable name when JSON is a string', () => {
    expect(() => parseJsonEnv('"just a string"', 'MY_VAR'))
      .toThrow('MY_VAR: invalid JSON');
  });

  it('throws with variable name when JSON is null', () => {
    expect(() => parseJsonEnv('null', 'MY_VAR'))
      .toThrow('MY_VAR: invalid JSON');
  });

  it('throws with variable name when JSON is a number', () => {
    expect(() => parseJsonEnv('123', 'MY_VAR'))
      .toThrow('MY_VAR: invalid JSON');
  });

  it('does NOT include the raw value in the error (no secret leakage)', () => {
    const SECRET_VALUE = '{"Authorization":"Bearer secret-key-must-not-appear"}broken';
    let errorMessage = '';
    try {
      parseJsonEnv(SECRET_VALUE, 'MY_HEADERS');
    } catch (err) {
      errorMessage = (err as Error).message;
    }
    expect(errorMessage).not.toContain('secret-key-must-not-appear');
    expect(errorMessage).toContain('MY_HEADERS');
  });
});

// ---------------------------------------------------------------------------
// isEmailSenderConfigured
// ---------------------------------------------------------------------------

describe('isEmailSenderConfigured', () => {
  it('returns false when env is empty', () => {
    expect(isEmailSenderConfigured({})).toBe(false);
  });

  it('returns false when only MFA_EMAIL_FROM is set (no backend)', () => {
    expect(isEmailSenderConfigured({ MFA_EMAIL_FROM: 'noreply@example.com' })).toBe(false);
  });

  it('returns false when MFA_EMAIL_FROM is missing even with backend', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({ EMAIL: binding })).toBe(false);
  });

  it('returns false when MFA_EMAIL_FROM is blank/whitespace', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({ MFA_EMAIL_FROM: '  ', EMAIL: binding })).toBe(false);
  });

  it('returns true when CF binding + MFA_EMAIL_FROM set (CF-only)', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({ MFA_EMAIL_FROM: 'noreply@example.com', EMAIL: binding })).toBe(true);
  });

  it('returns true when HTTP endpoint + MFA_EMAIL_FROM set (HTTP-only)', () => {
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    })).toBe(true);
  });

  it('returns true in auto mode when both CF and HTTP are configured', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: binding,
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    })).toBe(true);
  });

  it('returns false with provider=cloudflare when EMAIL binding is absent', () => {
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'cloudflare',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    })).toBe(false);
  });

  it('returns true with provider=cloudflare when EMAIL binding is present', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'cloudflare',
      EMAIL: binding,
    })).toBe(true);
  });

  it('returns false with provider=http when MFA_EMAIL_HTTP_ENDPOINT is absent', () => {
    const binding: CfEmailBinding = { send: vi.fn() };
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'http',
      EMAIL: binding,
    })).toBe(false);
  });

  it('returns true with provider=http when MFA_EMAIL_HTTP_ENDPOINT is set', () => {
    expect(isEmailSenderConfigured({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'http',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildEmailSenderFromEnv
// ---------------------------------------------------------------------------

describe('buildEmailSenderFromEnv', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns null when MFA_EMAIL_FROM is absent', () => {
    expect(buildEmailSenderFromEnv({})).toBeNull();
  });

  it('returns null when MFA_EMAIL_FROM is blank', () => {
    expect(buildEmailSenderFromEnv({ MFA_EMAIL_FROM: '   ' })).toBeNull();
  });

  it('returns null when MFA_EMAIL_FROM is set but no backend configured', () => {
    expect(buildEmailSenderFromEnv({ MFA_EMAIL_FROM: 'noreply@example.com' })).toBeNull();
  });

  it('returns a sender (wrapped in Retrying) when only CF binding is configured', () => {
    const binding: CfEmailBinding = { send: vi.fn().mockResolvedValue({ messageId: 'cf-001' }) };
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: binding,
    });
    expect(result).not.toBeNull();
    // Should be a RetryingEmailSender wrapping CloudflareEmailSender
    expect(result).toBeInstanceOf(RetryingEmailSender);
  });

  it('returns a sender (Retrying wrapping Http) when only HTTP endpoint is configured', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_AUTH: 'Bearer test-auth-token',
    });
    expect(result).not.toBeNull();
    expect(result).toBeInstanceOf(RetryingEmailSender);
    // Actually send to verify the HTTP sender is used
    await result!.send(sampleMessage);
    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://api.example.com/send');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer test-auth-token');
  });

  it('returns FallbackEmailSender with CF first when both auto + CF + HTTP configured', () => {
    const binding: CfEmailBinding = { send: vi.fn().mockResolvedValue({ messageId: 'cf-001' }) };
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: binding,
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    });
    expect(result).not.toBeNull();
    expect(result).toBeInstanceOf(FallbackEmailSender);
  });

  it('sends via CF first in auto mode when both backends configured (CF binding called, HTTP not)', async () => {
    const cfSend = vi.fn().mockResolvedValueOnce({ messageId: 'cf-001' });
    const binding: CfEmailBinding = { send: cfSend };
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      EMAIL: binding,
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    });
    await result!.send(sampleMessage);
    // CF binding is called first
    expect(cfSend).toHaveBeenCalledOnce();
    // HTTP fetch should NOT be called (CF succeeded)
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('provider=cloudflare without EMAIL binding returns null (no HTTP either)', () => {
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'cloudflare',
    });
    expect(result).toBeNull();
  });

  it('provider=cloudflare without EMAIL binding returns null even when MFA_EMAIL_HTTP_ENDPOINT is set', () => {
    // Bug guard: cloudflare provider requires the CF binding — HTTP fallback must NOT be used
    // when the caller explicitly requested cloudflare mode and the binding is absent.
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'cloudflare',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    });
    expect(result).toBeNull();
  });

  it('provider=http returns HTTP-only sender (no CF fallback even when binding present)', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const binding: CfEmailBinding = { send: vi.fn() };
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_PROVIDER: 'http',
      EMAIL: binding,
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
    });
    expect(result).not.toBeNull();
    await result!.send(sampleMessage);
    expect(mockFetch).toHaveBeenCalledOnce();
    expect(binding.send).not.toHaveBeenCalled();
  });

  it('throws on invalid JSON in MFA_EMAIL_HTTP_HEADERS including variable name in error', () => {
    expect(() => buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_HEADERS: 'not-valid-json',
    })).toThrow('MFA_EMAIL_HTTP_HEADERS: invalid JSON');
  });

  it('throws on invalid JSON in MFA_EMAIL_HTTP_BODY including variable name in error', () => {
    expect(() => buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_BODY: '{broken json',
    })).toThrow('MFA_EMAIL_HTTP_BODY: invalid JSON');
  });

  it('sets toAsArray=true when MFA_EMAIL_HTTP_TO_ARRAY=1', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_TO_ARRAY: '1',
    });
    await result!.send(sampleMessage);
    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body.to)).toBe(true);
  });

  it('sets toAsArray=true when MFA_EMAIL_HTTP_TO_ARRAY=true', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_TO_ARRAY: 'true',
    });
    await result!.send(sampleMessage);
    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body.to)).toBe(true);
  });

  it('sets toAsArray=true when MFA_EMAIL_HTTP_TO_ARRAY=yes', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'noreply@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_TO_ARRAY: 'yes',
    });
    await result!.send(sampleMessage);
    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body.to)).toBe(true);
  });

  it('returns null for fully empty env', () => {
    expect(buildEmailSenderFromEnv({})).toBeNull();
  });

  // --- MFA_EMAIL_HTTP_BODY_TEMPLATE 模板模式 ---

  it('picks up MFA_EMAIL_HTTP_BODY_TEMPLATE and uses template mode when valid JSON', async () => {
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = {
      from_address: '{{from}}',
      recipient: '{{to}}',
      subject_line: '{{subject}}',
      body: '{{text}}',
    };
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'sender@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_BODY_TEMPLATE: JSON.stringify(template),
    });
    expect(result).not.toBeNull();
    await result!.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.from_address).toBe('sender@example.com');
    expect(body.recipient).toBe('recipient@example.com');
    expect(body.subject_line).toBe('Test Subject');
    expect(body.body).toBe('Hello from test');
  });

  it('throws on invalid JSON in MFA_EMAIL_HTTP_BODY_TEMPLATE including variable name in error', () => {
    expect(() => buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'sender@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_BODY_TEMPLATE: '{not valid json',
    })).toThrow('MFA_EMAIL_HTTP_BODY_TEMPLATE: invalid JSON');
  });

  it('does not pick up MFA_EMAIL_HTTP_BODY_TEMPLATE when value is whitespace only', async () => {
    // 空白仅值 → 等同未配置，走扁平模式
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'sender@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_BODY_TEMPLATE: '   ',
    });
    expect(result).not.toBeNull();
    await result!.send(sampleMessage);
    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    // 扁平模式：顶层字段 from/to/subject/text
    expect(body.from).toBe('sender@example.com');
    expect(body.to).toBe('recipient@example.com');
  });

  it('accepts array-root MFA_EMAIL_HTTP_BODY_TEMPLATE (not treated as invalid JSON)', async () => {
    // buildHttpConfig 放开后顶层数组应被接受，不再抛 invalid JSON
    mockFetch.mockResolvedValueOnce(new Response('{}', { status: 200 }));
    const template = [{ from: '{{from}}', to: '{{to}}', subject: '{{subject}}', text: '{{text}}' }];
    const result = buildEmailSenderFromEnv({
      MFA_EMAIL_FROM: 'sender@example.com',
      MFA_EMAIL_HTTP_ENDPOINT: 'https://api.example.com/send',
      MFA_EMAIL_HTTP_BODY_TEMPLATE: JSON.stringify(template),
    });
    expect(result).not.toBeNull();
    await result!.send(sampleMessage);

    const body = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(Array.isArray(body)).toBe(true);
    expect(body[0].from).toBe('sender@example.com');
    expect(body[0].to).toBe('recipient@example.com');
  });
});
