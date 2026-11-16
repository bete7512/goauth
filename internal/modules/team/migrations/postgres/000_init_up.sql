-- Teams inside organizations. parent_id is '' for a top-level team; path
-- lists the team's ancestors and the team itself as "/<id>/<id>/", so a
-- sub-tree is a prefix match.
CREATE TABLE IF NOT EXISTS teams (
    id VARCHAR(36) PRIMARY KEY,
    org_id VARCHAR(36) NOT NULL,
    parent_id VARCHAR(36) NOT NULL DEFAULT '',
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description VARCHAR(1000) NOT NULL DEFAULT '',
    path VARCHAR(255) NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_org_slug ON teams (org_id, slug);
CREATE INDEX IF NOT EXISTS idx_teams_org_path ON teams (org_id, path);
CREATE INDEX IF NOT EXISTS idx_teams_parent ON teams (parent_id);

-- Who is in which team. membership_id is the organization membership the
-- row belongs to; the row stops counting when that membership ends.
CREATE TABLE IF NOT EXISTS team_members (
    id VARCHAR(36) PRIMARY KEY,
    team_id VARCHAR(36) NOT NULL,
    org_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',
    membership_id VARCHAR(36) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_team_member ON team_members (team_id, user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_org_user ON team_members (org_id, user_id);
