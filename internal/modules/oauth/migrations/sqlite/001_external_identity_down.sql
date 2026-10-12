DROP INDEX idx_accounts_connection_subject;
ALTER TABLE accounts DROP COLUMN issuer;
ALTER TABLE accounts DROP COLUMN realm_id;
