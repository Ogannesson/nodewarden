-- Migration 0004: TOTP replay protection — last-used counter tracking
--
-- Adds totp_last_counter to users. When a TOTP code is validated, the matched
-- counter value (floor(nowMs/30000) + delta) is written here. Subsequent attempts
-- with a counter ≤ this stored value are rejected, preventing ~90-second replay.
--
-- NULL means "no authenticated TOTP login yet" — all counters accepted on first use.
ALTER TABLE users ADD COLUMN totp_last_counter INTEGER;
