/**
 * email-sender.ts
 *
 * Pluggable EmailSender abstraction for transactional email (MFA codes, etc.).
 *
 * Supported backends (configured via env vars — no vendor hard-coded):
 *   1. Cloudflare Email Sending (env.EMAIL binding via [[send_email]])
 *   2. Generic HTTP endpoint (MFA_EMAIL_HTTP_ENDPOINT + optional auth/headers/body)
 *
 * Resilience: RetryingEmailSender (same-backend retry) + FallbackEmailSender
 * (cross-backend fallback) compose around the concrete senders.
 *
 * Design rules:
 * - Send failures MUST throw — never swallow silently.
 * - The interface is intentionally minimal; implementors may ignore fields they
 *   don't support (e.g. plain-text-only senders can ignore `html`).
 * - HTTP bodies are always constructed programmatically (never string-templated)
 *   to prevent JSON injection from user-controlled fields such as `to`.
 * - Secrets (auth headers, API keys) are never logged or included in thrown errors.
 */

import type { CfEmailBinding } from '../types';

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

export interface EmailSender {
  send(message: EmailMessage): Promise<void>;
}

// ---------------------------------------------------------------------------
// CloudflareEmailSender
// ---------------------------------------------------------------------------

/**
 * Sends email via the Cloudflare Email Sending binding (env.EMAIL).
 * Requires a [[send_email]] binding in wrangler.toml and a verified sending domain.
 */
export class CloudflareEmailSender implements EmailSender {
  constructor(
    private readonly binding: CfEmailBinding,
    private readonly from: string,
  ) {}

  async send(message: EmailMessage): Promise<void> {
    try {
      await this.binding.send({
        from: this.from,
        to: message.to,
        subject: message.subject,
        text: message.text,
        ...(message.html !== undefined ? { html: message.html } : {}),
      });
    } catch (err) {
      throw new Error(
        `Email send error (Cloudflare): ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// HttpEmailSender
// ---------------------------------------------------------------------------

export interface HttpEmailConfig {
  endpoint: string;
  method?: string;
  headers?: Record<string, string>;
  from: string;
  /** Remap logical field names to API-specific keys. Defaults to same name. */
  fieldMap?: { from?: string; to?: string; subject?: string; text?: string; html?: string };
  /** Wrap the 'to' address in an array (some APIs require `to: [addr]`). */
  toAsArray?: boolean;
  /** Static extra fields merged into every request body. */
  extraBody?: Record<string, unknown>;
  /** HTTP status codes treated as success. Defaults to any 2xx. */
  successStatuses?: number[];
}

/**
 * Sends email via a generic flat-JSON HTTP endpoint.
 *
 * Body is always constructed programmatically to prevent JSON injection
 * from user-supplied fields (e.g. the 'to' address). Secrets are never
 * logged or included in thrown error messages.
 *
 * Limitation: only flat JSON request bodies are supported. APIs with nested
 * structures (e.g. personalizations arrays) are out of scope and can be
 * addressed as a future enhancement.
 */
export class HttpEmailSender implements EmailSender {
  private readonly config: Required<Pick<HttpEmailConfig, 'endpoint' | 'method' | 'headers' | 'from' | 'toAsArray' | 'extraBody'>> & HttpEmailConfig;

  constructor(config: HttpEmailConfig) {
    this.config = {
      method: 'POST',
      headers: {},
      fieldMap: {},
      toAsArray: false,
      extraBody: {},
      successStatuses: undefined,
      ...config,
    };
  }

  async send(message: EmailMessage): Promise<void> {
    const { endpoint, method, headers, from, fieldMap = {}, toAsArray, extraBody = {}, successStatuses } = this.config;

    // Resolve field names (with defaults).
    const fFrom    = fieldMap.from    ?? 'from';
    const fTo      = fieldMap.to      ?? 'to';
    const fSubject = fieldMap.subject ?? 'subject';
    const fText    = fieldMap.text    ?? 'text';
    const fHtml    = fieldMap.html    ?? 'html';

    // Build body programmatically — never via string templates.
    const body: Record<string, unknown> = { ...extraBody };
    body[fFrom]    = from;
    body[fTo]      = toAsArray ? [message.to] : message.to;
    body[fSubject] = message.subject;
    body[fText]    = message.text;
    if (message.html !== undefined && !(fHtml in body)) {
      body[fHtml] = message.html;
    }

    let resp: Response;
    try {
      resp = await fetch(endpoint, {
        method: method ?? 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      // Network-level failure — must not be swallowed. No secrets in message.
      throw new Error(
        `Email send network error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    const isSuccess = successStatuses
      ? successStatuses.includes(resp.status)
      : resp.status >= 200 && resp.status < 300;

    if (!isSuccess) {
      let detail = '';
      try {
        const errBody = await resp.json() as Record<string, unknown>;
        detail = String(errBody?.message ?? errBody?.error ?? '');
      } catch {
        // Ignore JSON parse error; fall back to status text.
      }
      // Do not include headers or auth tokens in the error message.
      throw new Error(
        `Email send failed (HTTP ${resp.status}): ${detail || resp.statusText}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// RetryingEmailSender
// ---------------------------------------------------------------------------

/**
 * Wraps a single EmailSender with same-backend retry.
 * Default: 2 attempts (1 retry) with no backoff to avoid latency in login paths.
 */
export class RetryingEmailSender implements EmailSender {
  constructor(
    private readonly inner: EmailSender,
    private readonly maxAttempts: number = 2,
  ) {}

  async send(message: EmailMessage): Promise<void> {
    let lastErr: unknown;
    for (let i = 0; i < this.maxAttempts; i++) {
      try {
        return await this.inner.send(message);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr;
  }
}

// ---------------------------------------------------------------------------
// FallbackEmailSender
// ---------------------------------------------------------------------------

/**
 * Tries senders in priority order; falls back to the next on failure.
 * Logs a warning (without secrets) when a sender fails.
 * Throws the last error if all senders fail.
 */
export class FallbackEmailSender implements EmailSender {
  constructor(private readonly senders: EmailSender[]) {
    if (senders.length === 0) {
      throw new Error('FallbackEmailSender: senders list must not be empty');
    }
  }

  async send(message: EmailMessage): Promise<void> {
    let lastErr: unknown;
    for (let i = 0; i < this.senders.length; i++) {
      try {
        return await this.senders[i].send(message);
      } catch (err) {
        lastErr = err;
        // Warn without leaking any secret values.
        console.warn(
          `Email sender [${i}] failed, trying next: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
    throw lastErr;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse a JSON env var that must be an object.
 * Returns {} when the value is absent or empty.
 * Throws `<name>: invalid JSON` (without the value) on malformed input.
 */
export function parseJsonEnv(raw: string | undefined, name: string): Record<string, unknown> {
  if (!raw?.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${name}: invalid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${name}: invalid JSON`);
  }
  return parsed as Record<string, unknown>;
}

/** Build the HttpEmailConfig from env vars (used by buildEmailSenderFromEnv). */
function buildHttpConfig(
  env: {
    MFA_EMAIL_HTTP_ENDPOINT?: string;
    MFA_EMAIL_HTTP_AUTH?: string;
    MFA_EMAIL_HTTP_HEADERS?: string;
    MFA_EMAIL_HTTP_BODY?: string;
    MFA_EMAIL_HTTP_TO_ARRAY?: string;
  },
  from: string,
): HttpEmailConfig {
  const extraHeaders = parseJsonEnv(env.MFA_EMAIL_HTTP_HEADERS, 'MFA_EMAIL_HTTP_HEADERS') as Record<string, string>;
  const headers: Record<string, string> = {
    ...(env.MFA_EMAIL_HTTP_AUTH ? { Authorization: env.MFA_EMAIL_HTTP_AUTH } : {}),
    ...extraHeaders,
  };
  const extraBody = parseJsonEnv(env.MFA_EMAIL_HTTP_BODY, 'MFA_EMAIL_HTTP_BODY');
  const toAsArray = /^(1|true|yes)$/i.test((env.MFA_EMAIL_HTTP_TO_ARRAY ?? '').trim());

  return {
    endpoint: env.MFA_EMAIL_HTTP_ENDPOINT!,
    headers,
    from,
    extraBody,
    toAsArray,
  };
}

// ---------------------------------------------------------------------------
// isEmailSenderConfigured
// ---------------------------------------------------------------------------

/**
 * Single authoritative predicate: is the email sending stack configured on
 * this deployment?
 *
 * Used by all availability guards (isAvailable(), handler pre-checks).
 * Only checks existence — invalid JSON in HTTP config is caught at send time
 * (distinguishing "not configured" 503 from "misconfigured" 500).
 */
export function isEmailSenderConfigured(env: {
  MFA_EMAIL_FROM?: string;
  EMAIL?: CfEmailBinding;
  MFA_EMAIL_PROVIDER?: string;
  MFA_EMAIL_HTTP_ENDPOINT?: string;
}): boolean {
  if (!env.MFA_EMAIL_FROM?.trim()) return false;
  const provider = env.MFA_EMAIL_PROVIDER ?? 'auto';
  const cfAvail   = !!env.EMAIL;
  const httpAvail = !!env.MFA_EMAIL_HTTP_ENDPOINT;
  switch (provider) {
    case 'cloudflare': return cfAvail;
    case 'http':       return httpAvail;
    default:           return cfAvail || httpAvail; // auto
  }
}

// ---------------------------------------------------------------------------
// buildEmailSenderFromEnv (factory)
// ---------------------------------------------------------------------------

/**
 * Build an EmailSender from env vars, or null if not configured.
 *
 * Priority (auto mode): Cloudflare Email (primary) → generic HTTP (fallback).
 * Each backend is individually wrapped with RetryingEmailSender.
 * When both are present, FallbackEmailSender composes them.
 *
 * Callers use null to determine isAvailable() / return 503.
 */
export function buildEmailSenderFromEnv(env: {
  MFA_EMAIL_FROM?: string;
  EMAIL?: CfEmailBinding;
  MFA_EMAIL_PROVIDER?: string;
  MFA_EMAIL_HTTP_ENDPOINT?: string;
  MFA_EMAIL_HTTP_AUTH?: string;
  MFA_EMAIL_HTTP_HEADERS?: string;
  MFA_EMAIL_HTTP_BODY?: string;
  MFA_EMAIL_HTTP_TO_ARRAY?: string;
}): EmailSender | null {
  if (!env.MFA_EMAIL_FROM?.trim()) return null;
  const from     = env.MFA_EMAIL_FROM.trim();
  const provider = env.MFA_EMAIL_PROVIDER ?? 'auto';

  const cf   = env.EMAIL ? new CloudflareEmailSender(env.EMAIL, from) : null;
  const http = env.MFA_EMAIL_HTTP_ENDPOINT ? new HttpEmailSender(buildHttpConfig(env, from)) : null;

  const list: EmailSender[] = [];
  switch (provider) {
    case 'cloudflare':
      // CF is required — if binding is absent, this provider is not available (matches isEmailSenderConfigured).
      // HTTP may still act as fallback when CF is present.
      if (!cf) return null;
      list.push(cf);
      if (http) list.push(http);
      break;
    case 'http':
      // Explicit HTTP-only — no CF fallback even if binding is present.
      if (http) list.push(http);
      break;
    default:
      // auto: CF unconditionally preferred, HTTP as fallback.
      if (cf)   list.push(cf);
      if (http) list.push(http);
      break;
  }

  // Wrap each backend with per-backend retry.
  const retrying = list.map(s => new RetryingEmailSender(s));

  if (retrying.length === 0) return null;
  if (retrying.length === 1) return retrying[0];
  return new FallbackEmailSender(retrying);
}
