-- Migration: 0002_two_factors
-- Add two_factors table for multi-provider MFA (WebAuthn, Email, YubiKey…).
--
-- CONSERVATIVE DUAL-TRACK design (see docs/MFA-RESEARCH.md §4.1):
-- - TOTP continues to use users.totp_secret / totp_recovery_code (NOT migrated).
-- - This table is reserved for future providers: WebAuthn (atype=7), Email (1),
--   YubiKey (3). The primary key (user_id, atype) enforces one row per provider
--   per user, matching Vaultwarden's two_factor model.
--
-- IMPORTANT: sync this file with src/services/storage-schema.ts SCHEMA_STATEMENTS
-- and bump STORAGE_SCHEMA_VERSION in src/services/storage.ts when applying.
-- Keep statements idempotent.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS two_factors (
  user_id     TEXT    NOT NULL,
  atype       INTEGER NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 0,
  data        TEXT    NOT NULL DEFAULT '{}',
  last_used   INTEGER,
  created_at  TEXT    NOT NULL,
  updated_at  TEXT    NOT NULL,
  PRIMARY KEY (user_id, atype),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_two_factors_user ON two_factors(user_id);
