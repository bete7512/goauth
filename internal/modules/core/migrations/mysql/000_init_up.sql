CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    name TEXT NOT NULL DEFAULT (''),
    first_name TEXT NOT NULL DEFAULT (''),
    last_name TEXT NOT NULL DEFAULT (''),
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL DEFAULT (''),
    password TEXT NOT NULL,
    avatar TEXT NOT NULL DEFAULT (''),
    phone_number TEXT NOT NULL DEFAULT (''),
    active TINYINT(1) NOT NULL DEFAULT 1,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    phone_number_verified TINYINT(1) NOT NULL DEFAULT 0,
    is_super_admin TINYINT(1) NOT NULL DEFAULT 0,
    token_version INT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    updated_at DATETIME,
    UNIQUE INDEX idx_users_email (email),
    UNIQUE INDEX idx_users_username (username),
    INDEX idx_users_is_super_admin (is_super_admin)
);

CREATE TABLE IF NOT EXISTS extended_attributes (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ea_user_id (user_id),
    CONSTRAINT fk_ea_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    type VARCHAR(100) NOT NULL,
    token VARCHAR(255) NOT NULL,
    code VARCHAR(255) NOT NULL DEFAULT '',
    email VARCHAR(255) NOT NULL DEFAULT '',
    phone_number VARCHAR(50) NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_tokens_token (token),
    INDEX idx_tokens_user_id (user_id),
    INDEX idx_tokens_type (type),
    INDEX idx_tokens_code (code),
    INDEX idx_tokens_email (email),
    INDEX idx_tokens_phone_number (phone_number),
    INDEX idx_tokens_expires_at (expires_at)
);
