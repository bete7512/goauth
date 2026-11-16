package models

import (
	"context"
	"strings"
	"time"
)

// Team is a group of an organization's members. Teams nest: a team may have
// a parent team in the same organization, up to MaxTeamDepth levels.
type Team struct {
	ID    string `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID string `json:"org_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_teams_org_slug;index:idx_teams_org_path"`
	// ParentID is "" for a team at the top of the organization.
	ParentID    string `json:"parent_id,omitempty" gorm:"type:varchar(36);not null;default:'';index"`
	Name        string `json:"name" gorm:"type:varchar(255);not null"`
	Slug        string `json:"slug" gorm:"type:varchar(255);not null;uniqueIndex:idx_teams_org_slug"`
	Description string `json:"description,omitempty" gorm:"type:varchar(1000);not null;default:''"`
	// Path lists the team's ancestors and the team itself, top first, as
	// "/<id>/<id>/", so a team's whole sub-tree is the teams whose path
	// starts with its own.
	Path string `json:"path" gorm:"type:varchar(255);not null;index:idx_teams_org_path"`
	// Depth is 0 for a top-level team.
	Depth     int        `json:"depth" gorm:"not null;default:0"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// TableName specifies the database table for Team.
func (Team) TableName() string { return "teams" }

// MaxTeamDepth is how many levels of teams an organization may have.
const MaxTeamDepth = 5

// TeamPath returns the path of a team whose parent has parentPath; a
// top-level team passes "".
func TeamPath(parentPath, teamID string) string {
	if parentPath == "" {
		return "/" + teamID + "/"
	}
	return parentPath + teamID + "/"
}

// AncestorIDs returns the IDs on the team's path, top first, the team
// itself last.
func (t *Team) AncestorIDs() []string {
	return strings.FieldsFunc(t.Path, func(r rune) bool { return r == '/' })
}

// Team member roles.
const (
	// TeamRoleLead manages the team and every team beneath it.
	TeamRoleLead = "lead"
	// TeamRoleMember belongs to the team.
	TeamRoleMember = "member"
)

// ValidTeamRole reports whether role is a team member role.
func ValidTeamRole(role string) bool { return role == TeamRoleLead || role == TeamRoleMember }

// TeamMember is a user's place in a team. Only members of the team's
// organization can be in it; MembershipID is that organization membership,
// so the row stops counting if the user leaves the organization, even if
// they join it again later.
type TeamMember struct {
	ID           string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	TeamID       string     `json:"team_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_team_member"`
	OrgID        string     `json:"org_id" gorm:"type:varchar(36);not null;index:idx_team_members_org_user"`
	UserID       string     `json:"user_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_team_member;index:idx_team_members_org_user"`
	Role         string     `json:"role" gorm:"type:varchar(20);not null;default:'member'"`
	MembershipID string     `json:"-" gorm:"type:varchar(36);not null;default:''"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// TableName specifies the database table for TeamMember.
func (TeamMember) TableName() string { return "team_members" }

// TeamRepository persists teams.
type TeamRepository interface {
	// Create stores a team; a slug already used in the organization is
	// ErrConflict.
	Create(ctx context.Context, team *Team) error
	FindByID(ctx context.Context, id string) (*Team, error)
	// FindByIDs returns the teams that exist among ids, in no order.
	FindByIDs(ctx context.Context, ids []string) ([]*Team, error)
	// List lists an organization's teams.
	List(ctx context.Context, orgID string, opts TeamListOpts) ([]*Team, int64, error)
	// Subtree returns the teams whose path starts with path: a team and
	// everything beneath it.
	Subtree(ctx context.Context, orgID, path string) ([]*Team, error)
	// CountChildren counts the teams directly beneath a team.
	CountChildren(ctx context.Context, teamID string) (int64, error)
	// Update saves a team's name, slug and description.
	Update(ctx context.Context, team *Team) error
	// Move gives a team a new parent, path and depth, and rewrites the paths
	// and depths of everything beneath it, in one transaction.
	Move(ctx context.Context, team *Team, oldPath string) error
	// Delete removes a team and its memberships. It refuses (ErrConflict) a
	// team that still has teams beneath it.
	Delete(ctx context.Context, id string) error
	// DeleteByOrg removes every team of an organization and its memberships.
	DeleteByOrg(ctx context.Context, orgID string) error
}

// TeamMemberRepository persists team memberships.
type TeamMemberRepository interface {
	// Create adds a member; one already in the team is ErrConflict.
	Create(ctx context.Context, member *TeamMember) error
	FindByTeamAndUser(ctx context.Context, teamID, userID string) (*TeamMember, error)
	ListByTeam(ctx context.Context, teamID string, opts TeamMemberListOpts) ([]*TeamMember, int64, error)
	// ListByUser returns the user's memberships in an organization's teams.
	ListByUser(ctx context.Context, orgID, userID string) ([]*TeamMember, error)
	// ListByTeams returns the user's memberships among the given teams.
	ListByTeams(ctx context.Context, userID string, teamIDs []string) ([]*TeamMember, error)
	Update(ctx context.Context, member *TeamMember) error
	Delete(ctx context.Context, teamID, userID string) error
	// DeleteByOrgAndUser removes a user from every team of an organization,
	// for a user who left it.
	DeleteByOrgAndUser(ctx context.Context, orgID, userID string) error
	// DeleteByUser removes a deleted user from every team.
	DeleteByUser(ctx context.Context, userID string) error
}

// TeamListOpts lists an organization's teams.
type TeamListOpts struct {
	ListingOpts
	// ParentID lists only the teams directly beneath it; Top lists only the
	// top-level teams. With neither, every team is listed.
	ParentID string
	Top      bool
	Query    string // search name or slug
}

var teamSortFields = map[string]bool{"created_at": true, "name": true, "slug": true, "path": true}

// Normalize validates and clamps all fields.
func (o *TeamListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, teamSortFields)
	o.ParentID = strings.TrimSpace(o.ParentID)
	o.Query = strings.TrimSpace(o.Query)
}

// TeamMemberListOpts lists a team's members.
type TeamMemberListOpts struct {
	ListingOpts
	Role string
}

var teamMemberSortFields = map[string]bool{"created_at": true, "role": true}

// Normalize validates and clamps all fields.
func (o *TeamMemberListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, teamMemberSortFields)
	o.Role = strings.TrimSpace(o.Role)
}
