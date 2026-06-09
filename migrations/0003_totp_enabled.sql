-- Migration 0003: add totp_enabled flag to users table
-- Allows TOTP to be disabled without destroying the secret (reversible disable).
-- Existing rows default to 1 (enabled) so all users with a totp_secret remain active.
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 1;
