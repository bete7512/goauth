CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                 VARCHAR(36) PRIMARY KEY,
    user_id            VARCHAR(36) NOT NULL,
    credential_id      BYTEA NOT NULL,
    public_key         BYTEA NOT NULL,
    attestation_type   TEXT NOT NULL DEFAULT '',
    attestation_format TEXT NOT NULL DEFAULT '',
    aaguid             BYTEA,
    sign_count         BIGINT NOT NULL DEFAULT 0,
    transports         TEXT NOT NULL DEFAULT '',
    backup_eligible    BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state       BOOLEAN NOT NULL DEFAULT FALSE,
    user_present       BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    name               TEXT NOT NULL DEFAULT '',
    last_used_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_credentials_credential_id ON passkey_credentials (credential_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials (user_id);
