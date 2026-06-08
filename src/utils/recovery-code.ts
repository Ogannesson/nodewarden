/**
 * recovery-code.ts
 *
 * Recovery-code generation and verification.
 *
 * H4 — Storage security: recovery codes are stored as SHA-256 digests (hex) rather
 * than plaintext. The raw code is presented to the user exactly once at registration;
 * the server retains only the digest.
 *
 * Lazy migration strategy:
 *   When users.totp_recovery_code contains a 32-character base32 plaintext value
 *   (from before this migration), verifyRecoveryCode() recognises it as a legacy
 *   record and falls back to plaintext comparison.  On a successful match it returns
 *   the SHA-256 hash so the caller can persist the upgrade in a single round-trip.
 *   After upgrade, future logins use hash comparison only.
 *
 *   Detection heuristic: a SHA-256 hex digest is always exactly 64 lowercase hex
 *   characters.  A normalised recovery code is exactly 32 uppercase base32 chars.
 *   The two character sets do not overlap (hex uses a-f/0-9; base32 uses A-Z/2-7)
 *   so false classification is structurally impossible.
 */

const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RECOVERY_ALPHABET_LENGTH = RECOVERY_ALPHABET.length;
const RECOVERY_MAX_UNBIASED_BYTE = Math.floor(256 / RECOVERY_ALPHABET_LENGTH) * RECOVERY_ALPHABET_LENGTH;

/** Normalise a recovery-code string: strip non-base32 characters and uppercase. */
function normalizeRecoveryCode(raw: string): string {
  return String(raw || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function formatRecoveryCode(compact: string): string {
  return compact.replace(/(.{4})/g, '$1 ').trim();
}

/** Generate a cryptographically-random 32-character base32 recovery code. */
export function createRecoveryCode(): string {
  let compact = '';
  while (compact.length < 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    for (const b of bytes) {
      if (b >= RECOVERY_MAX_UNBIASED_BYTE) continue;
      compact += RECOVERY_ALPHABET[b % RECOVERY_ALPHABET_LENGTH];
      if (compact.length >= 32) break;
    }
  }
  return formatRecoveryCode(compact.slice(0, 32));
}

/**
 * Hash a recovery code for storage.
 *
 * Normalises the input first so that the hash is always computed over the
 * 32-character compact form regardless of spacing.
 *
 * Returns a 64-character lowercase hex string (SHA-256 of the compact code).
 */
export async function hashRecoveryCode(rawCode: string): Promise<string> {
  const compact = normalizeRecoveryCode(rawCode);
  const hashBuf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(compact)
  );
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * SHA-256 hex of the raw input WITHOUT recovery-code normalisation. Use this for
 * hashing numeric secrets such as email OTP codes: normalizeRecoveryCode() strips
 * non-base32 characters (0/1/8/9), which would collide distinct numeric codes and
 * make wrong codes compare equal. Every character of the input is significant here.
 */
export async function sha256Hex(input: string): Promise<string> {
  const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** True if a stored value looks like a SHA-256 hex digest (64 lowercase hex chars). */
function isHashedFormat(stored: string): boolean {
  return /^[0-9a-f]{64}$/.test(stored);
}

/**
 * Verify a submitted recovery code against the stored value.
 *
 * Supports both the new hashed format (64-char hex) and the legacy plaintext format
 * (32-char base32 after normalisation) for backward compatibility.
 *
 * Returns:
 *   - `match: false` if the code is wrong or no stored value exists.
 *   - `match: true, upgradedHash: undefined` if the stored value is already hashed.
 *   - `match: true, upgradedHash: <hex>` if the stored value was plaintext and the
 *     caller should now persist the upgraded hash to close the migration.
 *
 * Callers MUST treat `upgradedHash` as a write instruction:
 *   if (result.match && result.upgradedHash) { user.totpRecoveryCode = result.upgradedHash; saveUser(user); }
 */
export async function recoveryCodeEquals(
  input: string,
  storedCode: string | null | undefined
): Promise<{ match: boolean; upgradedHash?: string }> {
  if (!storedCode) return { match: false };

  const storedNorm = storedCode.trim();

  if (isHashedFormat(storedNorm)) {
    // New format: hash the input and compare digests.
    const inputHash = await hashRecoveryCode(input);
    const a = new TextEncoder().encode(inputHash);
    const b = new TextEncoder().encode(storedNorm);
    // Constant-time compare (same length guaranteed — both 64 chars).
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return { match: diff === 0 };
  }

  // Legacy plaintext format: compare normalised strings, then signal upgrade.
  // LAZY MIGRATION: this branch is reached only for rows that predate this change.
  // On successful match we return the upgraded hash so the caller can persist it.
  // After the row is upgraded, future calls always take the hashed branch above.
  const inputNorm = normalizeRecoveryCode(input);
  const storedLegacy = normalizeRecoveryCode(storedNorm);
  const a = new TextEncoder().encode(inputNorm);
  const b = new TextEncoder().encode(storedLegacy);
  if (a.length !== b.length) return { match: false };
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  if (diff !== 0) return { match: false };

  // Plaintext matched — compute hash for the caller to persist.
  const upgradedHash = await hashRecoveryCode(inputNorm);
  return { match: true, upgradedHash };
}
