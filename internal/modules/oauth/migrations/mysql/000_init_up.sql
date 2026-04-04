CREATE TABLE IF NOT EXISTS accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at DATETIME,
    token_type VARCHAR(50) NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT (''),
    id_token TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_accounts_user_id (user_id),
    INDEX idx_accounts_provider (provider)
);
