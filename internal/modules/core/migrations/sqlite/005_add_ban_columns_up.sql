ALTER TABLE users ADD COLUMN banned_at DATETIME;
ALTER TABLE users ADD COLUMN banned_until DATETIME;
ALTER TABLE users ADD COLUMN ban_reason VARCHAR(500) NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_users_banned_at ON users (banned_at);
