-- Roles created at runtime. org_id is '' for a role that belongs to the whole
-- application. Roles defined in code have no row.
CREATE TABLE IF NOT EXISTS rbac_roles (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL DEFAULT '',
    role_key VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    grants TEXT NOT NULL DEFAULT '[]',
    created_by VARCHAR(36) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_roles_org_key ON rbac_roles (org_id, role_key);

-- Who holds which role where. scope_id is '' for the global scope and the
-- organization ID for the org scope. The unique index also serves the lookup
-- behind every permission check (user_id first).
CREATE TABLE IF NOT EXISTS rbac_role_assignments (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    scope_id VARCHAR(36) NOT NULL DEFAULT '',
    role_key VARCHAR(64) NOT NULL,
    membership_id VARCHAR(36) NOT NULL DEFAULT '',
    granted_by VARCHAR(36) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_assignment ON rbac_role_assignments (user_id, scope_type, scope_id, role_key);
CREATE INDEX IF NOT EXISTS idx_rbac_assignment_scope ON rbac_role_assignments (scope_type, scope_id, role_key);
