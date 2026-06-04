/**
 * two-factor/registry.ts
 *
 * Provider registry: the ordered list of all TwoFactorProvider implementations.
 *
 * Usage:
 *   import { getAvailableProviders, getProvider } from './registry';
 *
 *   // For challenge generation:
 *   const providers = getAvailableProviders(env);
 *   // For token verification:
 *   const provider = getProvider(twoFactorProvider, env);
 *
 * To add a new provider (P1/P2): import it and append to ALL_PROVIDERS.
 * Providers are evaluated in order; first match wins for `getProvider`.
 */

import type { Env } from '../../types';
import type { TwoFactorProvider, TwoFactorTypeValue } from './types';
import { totpProvider } from './totp-provider';
import { webAuthnProvider } from './webauthn-provider';
import { emailProvider } from './email-provider';

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/**
 * ALL_PROVIDERS: ordered list of all known providers.
 * New providers are appended here as they are implemented (P3: YubiKey…).
 */
const ALL_PROVIDERS: readonly TwoFactorProvider[] = [
  totpProvider,
  webAuthnProvider, // P1: WebAuthn/FIDO2 (atype=7)
  emailProvider,    // P2: Email OTP (atype=1) — only active when an email backend is configured
  // P3: yubiKeyProvider will be added here
];

/**
 * Return all providers that are available on this deployment.
 * "Available" means the deployment has the required configuration (API keys, etc.).
 */
export function getAvailableProviders(env: Env): TwoFactorProvider[] {
  return ALL_PROVIDERS.filter(p => p.isAvailable(env));
}

/**
 * Return the provider for a given TwoFactorType value, or null if unknown/unavailable.
 */
export function getProvider(type: TwoFactorTypeValue | number, env: Env): TwoFactorProvider | null {
  return ALL_PROVIDERS.find(p => p.type === type && p.isAvailable(env)) ?? null;
}
