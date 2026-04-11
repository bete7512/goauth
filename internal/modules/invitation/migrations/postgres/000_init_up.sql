CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    purpose VARCHAR(100) NOT NULL DEFAULT 'platform',
    inviter_id VARCHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    metadata TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token ON invitations (token);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations (email);
CREATE INDEX IF NOT EXISTS idx_invitations_inviter_id ON invitations (inviter_id);
CREATE INDEX IF NOT EXISTS idx_invitations_purpose ON invitations (purpose);
