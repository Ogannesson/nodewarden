/**
 * storage-two-factor-repo.ts
 *
 * CRUD for the `two_factors` table.
 *
 * Conservative dual-track design: TOTP stays in users.totp_secret (not here).
 * This repo handles WebAuthn (atype=7), Email (atype=1), YubiKey (atype=3),
 * and any future provider types.
 *
 * Row model: (user_id, atype) PRIMARY KEY — one row per provider per user.
 * `data` is a JSON string; callers own parsing/serialisation of provider-specific config.
 */

export interface TwoFactorRow {
  userId: string;
  atype: number;
  enabled: boolean;
  /** Raw JSON string — provider owns parsing. */
  data: string;
  lastUsed: number | null;
  createdAt: string;
  updatedAt: string;
}

interface RawRow {
  user_id: string;
  atype: number;
  enabled: number;
  data: string;
  last_used: number | null;
  created_at: string;
  updated_at: string;
}

function rowToTwoFactor(raw: RawRow): TwoFactorRow {
  return {
    userId: raw.user_id,
    atype: raw.atype,
    enabled: raw.enabled !== 0,
    data: raw.data,
    lastUsed: raw.last_used ?? null,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

/**
 * Return the set of user IDs that have at least one enabled persistent two_factor row.
 *
 * C3: Used by admin list to accurately report twoFactorEnabled for all users at once,
 * avoiding an N+1 per-user query. Only persistent rows (atype < 1000) count.
 */
export async function getEnabledTwoFactorUserIds(db: D1Database): Promise<Set<string>> {
  const result = await db
    .prepare('SELECT DISTINCT user_id FROM two_factors WHERE enabled = 1 AND atype < 1000')
    .all<{ user_id: string }>();
  return new Set((result.results ?? []).map(r => r.user_id));
}

/** Return all two_factor rows for a user, any enabled state. */
export async function getTwoFactorsByUserId(db: D1Database, userId: string): Promise<TwoFactorRow[]> {
  const result = await db
    .prepare('SELECT user_id, atype, enabled, data, last_used, created_at, updated_at FROM two_factors WHERE user_id = ?')
    .bind(userId)
    .all<RawRow>();
  return (result.results ?? []).map(rowToTwoFactor);
}

/** Return the row for a specific (userId, atype), or null. */
export async function getTwoFactor(db: D1Database, userId: string, atype: number): Promise<TwoFactorRow | null> {
  const raw = await db
    .prepare('SELECT user_id, atype, enabled, data, last_used, created_at, updated_at FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(userId, atype)
    .first<RawRow>();
  return raw ? rowToTwoFactor(raw) : null;
}

/** Insert or replace a two_factor row (upsert by PK). */
export async function upsertTwoFactor(db: D1Database, row: TwoFactorRow): Promise<void> {
  await db
    .prepare(
      'INSERT INTO two_factors (user_id, atype, enabled, data, last_used, created_at, updated_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(user_id, atype) DO UPDATE SET ' +
      'enabled = excluded.enabled, data = excluded.data, last_used = excluded.last_used, updated_at = excluded.updated_at'
    )
    .bind(
      row.userId,
      row.atype,
      row.enabled ? 1 : 0,
      row.data,
      row.lastUsed ?? null,
      row.createdAt,
      row.updatedAt
    )
    .run();
}

/** Delete a specific (userId, atype) row. Returns true if a row was deleted. */
export async function deleteTwoFactor(db: D1Database, userId: string, atype: number): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM two_factors WHERE user_id = ? AND atype = ?')
    .bind(userId, atype)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

/** Delete all two_factor rows for a user (cascade is also set at DB level). */
export async function deleteAllTwoFactorsByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM two_factors WHERE user_id = ?')
    .bind(userId)
    .run();
  return result.meta?.changes ?? 0;
}

/**
 * Delete all transient challenge rows for a user (atype >= 1000).
 *
 * C4: Called after a successful TOTP/WebAuthn login to clean up any pending
 * Email OTP challenge rows. Prevents a previously-issued Email OTP from being
 * replayed through provider=1 after the user has already authenticated with
 * a different factor.
 */
export async function deleteTransientTwoFactorsByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM two_factors WHERE user_id = ? AND atype >= 1000')
    .bind(userId)
    .run();
  return result.meta?.changes ?? 0;
}

/** Update last_used timestamp for a specific (userId, atype). */
export async function touchTwoFactorLastUsed(db: D1Database, userId: string, atype: number, nowMs: number): Promise<void> {
  await db
    .prepare('UPDATE two_factors SET last_used = ?, updated_at = ? WHERE user_id = ? AND atype = ?')
    .bind(nowMs, new Date(nowMs).toISOString(), userId, atype)
    .run();
}
