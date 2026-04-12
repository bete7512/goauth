CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    owner_id VARCHAR(36) NOT NULL,
    logo_url VARCHAR(512),
    metadata TEXT,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_slug ON organizations (slug);
CREATE INDEX IF NOT EXISTS idx_organizations_owner_id ON organizations (owner_id);

CREATE TABLE IF NOT EXISTS organization_members (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_member ON organization_members (org_id, user_id);
CREATE INDEX IF NOT EXISTS idx_organization_members_user_id ON organization_members (user_id);

CREATE TABLE IF NOT EXISTS org_invitations (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    inviter_id VARCHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invitations_token ON org_invitations (token);
CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id ON org_invitations (org_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON org_invitations (email);
