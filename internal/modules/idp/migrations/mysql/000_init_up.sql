-- client_id is a case-sensitive identifier, so its columns use a binary
-- collation instead of the server's case-insensitive default.
CREATE TABLE IF NOT EXISTS idp_clients (
    id VARCHAR(36) PRIMARY KEY,
    client_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    secret_hash VARCHAR(255) NOT NULL DEFAULT '',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_uris TEXT NOT NULL,
    scopes TEXT NOT NULL,
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    skip_consent BOOLEAN NOT NULL DEFAULT FALSE,
    logo_uri TEXT NOT NULL,
    client_uri TEXT NOT NULL,
    managed BOOLEAN NOT NULL DEFAULT FALSE,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_idp_clients_client_id (client_id)
);

CREATE TABLE IF NOT EXISTS idp_grants (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    client_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    scopes TEXT NOT NULL,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_idp_grants_user_client (user_id, client_id),
    INDEX idx_idp_grants_client_id (client_id)
);
