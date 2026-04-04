CREATE TABLE IF NOT EXISTS two_factors (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    secret TEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    verified TINYINT(1) NOT NULL DEFAULT 0,
    method VARCHAR(20) NOT NULL DEFAULT 'totp',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_two_factors_user_id (user_id)
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    code TEXT NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_codes_user_id (user_id)
);
