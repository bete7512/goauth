DROP INDEX idx_users_banned_at ON users;
ALTER TABLE users DROP COLUMN ban_reason;
ALTER TABLE users DROP COLUMN banned_until;
ALTER TABLE users DROP COLUMN banned_at;
