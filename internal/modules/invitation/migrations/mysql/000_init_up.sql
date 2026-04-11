CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    purpose VARCHAR(100) NOT NULL DEFAULT 'platform',
    inviter_id VARCHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    metadata TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at TIMESTAMP NULL,
    UNIQUE INDEX idx_invitations_token (token),
    INDEX idx_invitations_email (email),
    INDEX idx_invitations_inviter_id (inviter_id),
    INDEX idx_invitations_purpose (purpose)
);
