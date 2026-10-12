CREATE TABLE IF NOT EXISTS passkey_credentials (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL,
    credential_id      BLOB NOT NULL,
    public_key         BLOB NOT NULL,
    attestation_type   TEXT NOT NULL DEFAULT '',
    attestation_format TEXT NOT NULL DEFAULT '',
    aaguid             BLOB,
    sign_count         INTEGER NOT NULL DEFAULT 0,
    transports         TEXT NOT NULL DEFAULT '',
    backup_eligible    INTEGER NOT NULL DEFAULT 0,
    backup_state       INTEGER NOT NULL DEFAULT 0,
    user_present       INTEGER NOT NULL DEFAULT 0,
    user_verified      INTEGER NOT NULL DEFAULT 0,
    name               TEXT NOT NULL DEFAULT '',
    last_used_at       DATETIME,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_credentials_credential_id ON passkey_credentials (credential_id);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials (user_id);
