DROP INDEX IF EXISTS idx_users_locked_until;
-- SQLite does not support DROP COLUMN before 3.35.0; for older versions, recreate the table.
ALTER TABLE users DROP COLUMN locked_until;
ALTER TABLE users DROP COLUMN failed_login_attempts;
