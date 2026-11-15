-- Roles created at runtime. org_id is '' for a role that belongs to the whole
-- application. Roles defined in code have no row.
-- role_key is a case-sensitive identifier, so its columns use a binary
-- collation instead of the server's case-insensitive default.
CREATE TABLE IF NOT EXISTS rbac_roles (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL DEFAULT '',
    role_key VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    grants TEXT NOT NULL,
    created_by VARCHAR(36) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL,
    UNIQUE INDEX idx_rbac_roles_org_key (org_id, role_key)
);

-- Who holds which role where. scope_id is '' for the global scope and the
-- organization ID for the org scope. The unique index also serves the lookup
-- behind every permission check (user_id first).
CREATE TABLE IF NOT EXISTS rbac_role_assignments (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    scope_id VARCHAR(36) NOT NULL DEFAULT '',
    role_key VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    membership_id VARCHAR(36) NOT NULL DEFAULT '',
    granted_by VARCHAR(36) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_rbac_assignment (user_id, scope_type, scope_id, role_key),
    INDEX idx_rbac_assignment_scope (scope_type, scope_id, role_key)
);
