CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL,
    avatar TEXT NOT NULL DEFAULT '',
    phone_number TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    email_verified INTEGER NOT NULL DEFAULT 0,
    phone_number_verified INTEGER NOT NULL DEFAULT 0,
    is_super_admin INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    updated_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_is_super_admin ON users (is_super_admin);

CREATE TABLE IF NOT EXISTS extended_attributes (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ea_user_id ON extended_attributes (user_id);

CREATE TABLE IF NOT EXISTS tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    type TEXT NOT NULL,
    token TEXT NOT NULL,
    code TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    phone_number TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_token ON tokens (token);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_type ON tokens (type);
CREATE INDEX IF NOT EXISTS idx_tokens_code ON tokens (code);
CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens (email);
CREATE INDEX IF NOT EXISTS idx_tokens_phone_number ON tokens (phone_number);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens (expires_at);
