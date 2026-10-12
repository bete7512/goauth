CREATE TABLE goauth_outbox (
 id VARCHAR(36) PRIMARY KEY,
 envelope TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 lease_id VARCHAR(36) NOT NULL DEFAULT '',
 available_at TIMESTAMP NOT NULL,
 created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_goauth_outbox_available ON goauth_outbox (available_at);
