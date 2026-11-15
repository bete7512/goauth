CREATE TABLE IF NOT EXISTS idp_clients (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL DEFAULT '',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    scopes TEXT NOT NULL DEFAULT '[]',
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    skip_consent BOOLEAN NOT NULL DEFAULT FALSE,
    logo_uri TEXT NOT NULL DEFAULT '',
    client_uri TEXT NOT NULL DEFAULT '',
    managed BOOLEAN NOT NULL DEFAULT FALSE,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_idp_clients_client_id ON idp_clients (client_id);

CREATE TABLE IF NOT EXISTS idp_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    last_used_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_idp_grants_user_client ON idp_grants (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_idp_grants_client_id ON idp_grants (client_id);
