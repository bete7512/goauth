DROP INDEX idx_accounts_connection_subject ON accounts;
ALTER TABLE accounts DROP COLUMN issuer;
ALTER TABLE accounts DROP COLUMN realm_id;
