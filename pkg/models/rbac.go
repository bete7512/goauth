package models

//go:generate mockgen -destination=../../internal/mocks/mock_rbac_repository.go -package=mocks github.com/bete7512/goauth/pkg/models RoleRepository,RoleAssignmentRepository

import (
	"context"
	"strings"
	"time"
)

// Scopes a role assignment can be made in.
const (
	// RoleScopeGlobal covers the whole application; ScopeID is empty.
	RoleScopeGlobal = "global"
	// RoleScopeOrg covers one organization; ScopeID is the organization ID.
	RoleScopeOrg = "org"
)

// Role is a role created at runtime. Roles defined in code are not stored.
// OrgID is empty for a role that belongs to the whole application.
type Role struct {
	ID          string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID       string     `json:"org_id" gorm:"type:varchar(36);not null;default:'';uniqueIndex:idx_rbac_roles_org_key"`
	Key         string     `json:"key" gorm:"column:role_key;type:varchar(64);not null;uniqueIndex:idx_rbac_roles_org_key"`
	Name        string     `json:"name" gorm:"type:varchar(255);not null"`
	Description string     `json:"description" gorm:"type:text"`
	Grants      StringList `json:"grants" gorm:"type:text;not null"`
	CreatedBy   string     `json:"created_by" gorm:"type:varchar(36);not null;default:''"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// TableName specifies the database table for Role.
func (Role) TableName() string { return "rbac_roles" }

// RoleAssignment gives a user a role in one scope. The role is named by key
// because roles defined in code have no row of their own.
//
// MembershipID is the organization membership the assignment was made for.
// An assignment only counts while that membership exists, so leaving an
// organization and joining it again never revives old roles.
type RoleAssignment struct {
	ID           string    `json:"id" gorm:"primaryKey;type:varchar(36)"`
	UserID       string    `json:"user_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_rbac_assignment"`
	ScopeType    string    `json:"scope_type" gorm:"type:varchar(16);not null;uniqueIndex:idx_rbac_assignment"`
	ScopeID      string    `json:"scope_id" gorm:"type:varchar(36);not null;default:'';uniqueIndex:idx_rbac_assignment"`
	RoleKey      string    `json:"role" gorm:"column:role_key;type:varchar(64);not null;uniqueIndex:idx_rbac_assignment"`
	MembershipID string    `json:"-" gorm:"type:varchar(36);not null;default:''"`
	GrantedBy    string    `json:"granted_by" gorm:"type:varchar(36);not null;default:''"`
	CreatedAt    time.Time `json:"created_at"`
}

// TableName specifies the database table for RoleAssignment.
func (RoleAssignment) TableName() string { return "rbac_role_assignments" }

// RoleScopeRef names one scope in a query for a user's assignments.
type RoleScopeRef struct {
	Type string
	ID   string
}

// RoleListOpts extends ListingOpts with role-specific filters.
type RoleListOpts struct {
	ListingOpts
	Query string // search key and name
}

// Normalize validates and clamps all fields.
func (o *RoleListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, roleSortFields)
	o.Query = strings.TrimSpace(o.Query)
}

// RoleAssignmentListOpts extends ListingOpts with assignment-specific filters.
type RoleAssignmentListOpts struct {
	ListingOpts
	UserID  string // filter by user
	RoleKey string // filter by role
}

// Normalize validates and clamps all fields.
func (o *RoleAssignmentListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, roleAssignmentSortFields)
	o.UserID = strings.TrimSpace(o.UserID)
	o.RoleKey = strings.TrimSpace(o.RoleKey)
}

var roleSortFields = map[string]bool{
	"created_at": true,
	"key":        true,
	"name":       true,
}

var roleAssignmentSortFields = map[string]bool{
	"created_at": true,
	"role_key":   true,
	"user_id":    true,
}

// RoleRepository persists roles created at runtime.
type RoleRepository interface {
	// Create stores a role. It returns ErrConflict when the organization
	// already has a role with that key.
	Create(ctx context.Context, role *Role) error
	// FindByKey returns ErrNotFound when the organization has no such role.
	FindByKey(ctx context.Context, orgID, key string) (*Role, error)
	// FindByKeys returns the roles of one organization that have these keys.
	FindByKeys(ctx context.Context, orgID string, keys []string) ([]*Role, error)
	ListByOrg(ctx context.Context, orgID string) ([]*Role, error)
	CountByOrg(ctx context.Context, orgID string) (int64, error)
	Update(ctx context.Context, role *Role) error
	Delete(ctx context.Context, id string) error
	DeleteByOrg(ctx context.Context, orgID string) error
}

// RoleAssignmentRepository persists which user holds which role where.
type RoleAssignmentRepository interface {
	// Create stores an assignment. It returns ErrConflict when the user
	// already holds the role in that scope.
	Create(ctx context.Context, assignment *RoleAssignment) error
	// ListByUser returns the user's assignments in the given scopes.
	ListByUser(ctx context.Context, userID string, scopes []RoleScopeRef) ([]*RoleAssignment, error)
	ListByScope(ctx context.Context, scopeType, scopeID string, opts RoleAssignmentListOpts) ([]*RoleAssignment, int64, error)
	Delete(ctx context.Context, userID, scopeType, scopeID, roleKey string) error
	DeleteByRole(ctx context.Context, scopeType, scopeID, roleKey string) error
	DeleteByUserAndScope(ctx context.Context, userID, scopeType, scopeID string) error
	DeleteByUser(ctx context.Context, userID string) error
	DeleteByScope(ctx context.Context, scopeType, scopeID string) error
}
