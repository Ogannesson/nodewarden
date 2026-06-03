/**
 * email-sender.ts
 *
 * Pluggable EmailSender abstraction for transactional email (MFA codes, etc.).
 *
 * Default implementation: Resend (https://resend.com) via REST API.
 * Required env vars: RESEND_API_KEY, MFA_EMAIL_FROM
 *
 * Design rules:
 * - Send failures MUST throw — never swallow silently.
 * - The interface is intentionally minimal; implementors may ignore fields they
 *   don't support (e.g. plain-text-only senders can ignore `html`).
 */

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
// Resend implementation
// ---------------------------------------------------------------------------

/** Default Resend REST API endpoint. */
const RESEND_API_URL = 'https://api.resend.com/emails';

/**
 * ResendEmailSender — sends email via the Resend REST API.
 *
 * Throws if the API call fails or returns a non-2xx status.
 *
 * For local testing, override the API endpoint via the `baseUrl` constructor
 * parameter (or set `RESEND_BASE_URL` env var in buildEmailSenderFromEnv).
 * Example: point to a mock server at http://localhost:9876/emails.
 */
export class ResendEmailSender implements EmailSender {
  private readonly endpointUrl: string;

  constructor(
    private readonly apiKey: string,
    private readonly from: string,
    /** Optional base URL override — defaults to https://api.resend.com/emails */
    baseUrl?: string,
  ) {
    this.endpointUrl = baseUrl ?? RESEND_API_URL;
  }

  async send(message: EmailMessage): Promise<void> {
    const body = {
      from: this.from,
      to: [message.to],
      subject: message.subject,
      text: message.text,
      ...(message.html ? { html: message.html } : {}),
    };

    let resp: Response;
    try {
      resp = await fetch(this.endpointUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
    } catch (err) {
      // Network-level failure — must not be swallowed.
      throw new Error(
        `Email send network error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    if (!resp.ok) {
      let detail = '';
      try {
        const errBody = await resp.json() as Record<string, unknown>;
        detail = String(errBody?.message ?? errBody?.error ?? '');
      } catch {
        // ignore JSON parse error; use status text
      }
      throw new Error(
        `Email send failed (HTTP ${resp.status}): ${detail || resp.statusText}`
      );
    }
  }
}

/**
 * Build an EmailSender from env vars, or null if not configured.
 * Callers use null to determine isAvailable().
 */
export function buildEmailSenderFromEnv(env: {
  RESEND_API_KEY?: string;
  MFA_EMAIL_FROM?: string;
  /** Optional base URL override — useful for local dev/CI mock servers. */
  RESEND_BASE_URL?: string;
}): EmailSender | null {
  if (!env.RESEND_API_KEY || !env.MFA_EMAIL_FROM) return null;
  return new ResendEmailSender(env.RESEND_API_KEY, env.MFA_EMAIL_FROM, env.RESEND_BASE_URL);
}
