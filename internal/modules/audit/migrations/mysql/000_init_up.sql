CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    actor_type VARCHAR(20) NOT NULL DEFAULT 'user',
    target_id VARCHAR(36),
    target_type VARCHAR(50),
    details TEXT NOT NULL DEFAULT (''),
    metadata JSON,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT (''),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_logs_action (action),
    INDEX idx_audit_logs_actor_id (actor_id),
    INDEX idx_audit_logs_target_id (target_id),
    INDEX idx_audit_logs_severity (severity),
    INDEX idx_audit_logs_created_at (created_at)
);
