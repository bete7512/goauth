DROP INDEX idx_users_locked_until ON users;
ALTER TABLE users DROP COLUMN locked_until;
ALTER TABLE users DROP COLUMN failed_login_attempts;
