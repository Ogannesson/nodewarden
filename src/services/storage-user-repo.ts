import type { User } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
const USER_SELECT_COLUMNS =
  'id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, ' +
  'kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, ' +
  'totp_secret, totp_enabled, totp_recovery_code, totp_last_counter, api_key, created_at, updated_at';

function mapUserRow(row: any): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    masterPasswordHint: row.master_password_hint ?? null,
    masterPasswordHash: row.master_password_hash,
    key: row.key,
    privateKey: row.private_key,
    publicKey: row.public_key,
    kdfType: row.kdf_type,
    kdfIterations: row.kdf_iterations,
    kdfMemory: row.kdf_memory ?? undefined,
    kdfParallelism: row.kdf_parallelism ?? undefined,
    securityStamp: row.security_stamp,
    role: row.role === 'admin' ? 'admin' : 'user',
    status: row.status === 'banned' ? 'banned' : 'active',
    verifyDevices: row.verify_devices == null ? true : !!row.verify_devices,
    totpSecret: row.totp_secret ?? null,
    // totp_enabled defaults to 1 in the DB; treat NULL (pre-migration rows) as enabled.
    totpEnabled: row.totp_enabled == null ? true : row.totp_enabled !== 0,
    totpRecoveryCode: row.totp_recovery_code ?? null,
    totpLastCounter: row.totp_last_counter ?? null,
    apiKey: row.api_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getUser(db: D1Database, email: string): Promise<User | null> {
  const row = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users WHERE email = ?`)
    .bind(email.toLowerCase())
    .first<any>();
  if (!row) return null;
  return mapUserRow(row);
}

export async function getUserById(db: D1Database, id: string): Promise<User | null> {
  const row = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users WHERE id = ?`)
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapUserRow(row);
}

export async function getUserCount(db: D1Database): Promise<number> {
  const row = await db.prepare('SELECT COUNT(*) AS count FROM users').first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function getAllUsers(db: D1Database): Promise<User[]> {
  const res = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users ORDER BY created_at ASC`)
    .all<any>();
  return (res.results || []).map((row) => mapUserRow(row));
}

export async function saveUser(db: D1Database, safeBind: SafeBind, user: User): Promise<void> {
  const email = user.email.toLowerCase();
  const stmt = db.prepare(
    'INSERT INTO users(id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_enabled, totp_recovery_code, api_key, created_at, updated_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'email=excluded.email, name=excluded.name, master_password_hint=excluded.master_password_hint, master_password_hash=excluded.master_password_hash, key=excluded.key, private_key=excluded.private_key, public_key=excluded.public_key, ' +
    'kdf_type=excluded.kdf_type, kdf_iterations=excluded.kdf_iterations, kdf_memory=excluded.kdf_memory, kdf_parallelism=excluded.kdf_parallelism, security_stamp=excluded.security_stamp, role=excluded.role, status=excluded.status, verify_devices=excluded.verify_devices, totp_secret=excluded.totp_secret, totp_enabled=excluded.totp_enabled, totp_recovery_code=excluded.totp_recovery_code, api_key=excluded.api_key, updated_at=excluded.updated_at'
  );
  await safeBind(
    stmt,
    user.id,
    email,
    user.name,
    user.masterPasswordHint,
    user.masterPasswordHash,
    user.key,
    user.privateKey,
    user.publicKey,
    user.kdfType,
    user.kdfIterations,
    user.kdfMemory,
    user.kdfParallelism,
    user.securityStamp,
    user.role,
    user.status,
    user.verifyDevices ? 1 : 0,
    user.totpSecret,
    user.totpEnabled ? 1 : 0,
    user.totpRecoveryCode,
    user.apiKey,
    user.createdAt,
    user.updatedAt
  ).run();
}

export async function createUser(db: D1Database, safeBind: SafeBind, user: User): Promise<void> {
  await saveUser(db, safeBind, user);
}

export async function createFirstUser(db: D1Database, safeBind: SafeBind, user: User): Promise<boolean> {
  const email = user.email.toLowerCase();
  const stmt = db.prepare(
    'INSERT INTO users(id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_enabled, totp_recovery_code, api_key, created_at, updated_at) ' +
    'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ' +
    'WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)'
  );
  const result = await safeBind(
    stmt,
    user.id,
    email,
    user.name,
    user.masterPasswordHint,
    user.masterPasswordHash,
    user.key,
    user.privateKey,
    user.publicKey,
    user.kdfType,
    user.kdfIterations,
    user.kdfMemory,
    user.kdfParallelism,
    user.securityStamp,
    user.role,
    user.status,
    user.verifyDevices ? 1 : 0,
    user.totpSecret,
    user.totpEnabled ? 1 : 0,
    user.totpRecoveryCode,
    user.apiKey,
    user.createdAt,
    user.updatedAt
  ).run();

  return (result.meta.changes ?? 0) > 0;
}

export async function deleteUserById(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Atomically claim a TOTP counter for replay protection.
 *
 * Uses a conditional UPDATE so that the check-and-write is atomic at the
 * database level, eliminating the TOCTOU window that existed when the caller
 * compared `totpLastCounter` in application memory and then wrote unconditionally.
 *
 * Returns `true` when the counter was actually written (the row existed and
 * `counter` is strictly greater than the stored value, or the stored value was
 * NULL).  Returns `false` when another concurrent request already claimed the
 * same counter (changes === 0), which the caller must treat as a replay.
 */
export async function updateTotpLastCounter(
  db: D1Database,
  userId: string,
  counter: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE users
          SET totp_last_counter = ?,
              updated_at        = ?
        WHERE id = ?
          AND (totp_last_counter IS NULL OR totp_last_counter < ?)`,
    )
    .bind(counter, new Date().toISOString(), userId, counter)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Atomically consume a recovery code for TOTP disable (login escape hatch).
 *
 * Uses a conditional UPDATE so the check-and-write is atomic at the database
 * level, eliminating the TOCTOU window that existed when callers compared the
 * stored hash in application memory and then wrote unconditionally.
 *
 * Returns `true` when the code was actually consumed (changes > 0).
 * Returns `false` when another concurrent request already consumed it
 * (changes === 0), which the caller MUST treat as failure (fail-closed).
 */
export async function atomicConsumeRecoveryCode(
  db: D1Database,
  userId: string,
  storedCode: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE users
          SET totp_recovery_code = NULL,
              totp_secret        = NULL,
              updated_at         = ?
        WHERE id = ?
          AND totp_recovery_code = ?`,
    )
    .bind(new Date().toISOString(), userId, storedCode)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Atomically rotate a recovery code (account recovery / escape hatch flow).
 *
 * Wipes TOTP secret, re-enables TOTP with a fresh recovery code and a new
 * security stamp — all in one conditional UPDATE keyed on the old stored hash.
 * Returns `false` when another concurrent request already rotated the code
 * (changes === 0), which the caller MUST treat as failure (fail-closed).
 */
export async function atomicRotateRecoveryCode(
  db: D1Database,
  userId: string,
  oldStoredCode: string,
  newHashedCode: string,
  newSecurityStamp: string,
  updatedAt: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE users
          SET totp_recovery_code = ?,
              totp_secret        = NULL,
              totp_enabled       = 1,
              security_stamp     = ?,
              updated_at         = ?
        WHERE id = ?
          AND totp_recovery_code = ?`,
    )
    .bind(newHashedCode, newSecurityStamp, updatedAt, userId, oldStoredCode)
    .run();
  return (result.meta.changes ?? 0) > 0;
}
