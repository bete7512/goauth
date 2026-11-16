DROP INDEX IF EXISTS idx_users_banned_at;
-- SQLite does not support DROP COLUMN before 3.35.0; for older versions, recreate the table.
ALTER TABLE users DROP COLUMN ban_reason;
ALTER TABLE users DROP COLUMN banned_until;
ALTER TABLE users DROP COLUMN banned_at;
