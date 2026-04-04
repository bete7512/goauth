CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    refresh_token VARCHAR(512) NOT NULL,
    refresh_token_expires_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    user_agent TEXT NOT NULL DEFAULT (''),
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    replaced_by VARCHAR(36) NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_sessions_refresh_token (refresh_token(255)),
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_refresh_token_expires_at (refresh_token_expires_at),
    INDEX idx_sessions_expires_at (expires_at)
);
