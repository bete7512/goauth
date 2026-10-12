ALTER TABLE accounts ADD COLUMN realm_id VARCHAR(64) NOT NULL DEFAULT 'default';
ALTER TABLE accounts ADD COLUMN issuer TEXT;
CREATE UNIQUE INDEX idx_accounts_connection_subject ON accounts (provider, provider_account_id);
