package rbac

import (
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/types"
)

// Types shared with callbacks and role definitions.
type (
	// Role is a named set of grants defined in code.
	Role = access.Role
	// ScopeType says where a role applies.
	ScopeType = access.ScopeType
	// Check describes one authorization decision; every callback receives it.
	Check = access.Check
	// Condition is a rule of the application's own attached to one check.
	Condition = access.Condition
	// Decision is what a Decide callback returns: Keep, Allow() or Deny(reason).
	Decision = access.Decision
	// DecideFunc sees every decision and may keep, allow or deny it.
	DecideFunc = access.DecideFunc
)

// Scopes a role can be limited to. The zero value allows both.
const (
	ScopeGlobal = access.ScopeGlobal
	ScopeOrg    = access.ScopeOrg
)

// Keep leaves a decision as the roles and conditions reached it.
var Keep = access.Keep

// Allow grants a request whatever the roles said.
func Allow() Decision { return access.Allow() }

// Deny refuses a request. The reason is returned to the caller.
func Deny(reason string) Decision { return access.Deny(reason) }

// Permissions lists, per resource, the actions the application checks. It is
// only needed for Strict mode; without it permissions are declared where
// they are used.
type Permissions map[string][]string

// Default limits. They bound how much one check has to read.
const (
	DefaultMaxRolesPerScope = 100
	DefaultMaxGrantsPerRole = 100
	DefaultMaxRolesPerUser  = 20
)

// Config holds configuration for the rbac module. The zero value works:
// permissions are declared where they are used, and the only roles are the
// built-in ones.
type Config struct {
	// Organizations turns on roles inside organizations. It requires the
	// organization module: a member's owner, admin or member role becomes a
	// built-in role, and custom roles can be created and assigned per
	// organization. When false, every role is application-wide.
	Organizations bool

	// Roles are roles defined in code. They can be assigned but not changed
	// through the API. A role with the key "owner", "admin" or "member" that
	// applies to organizations replaces what that membership role grants.
	Roles []Role

	// Permissions and Strict give a fixed catalog. With Strict set, a
	// permission that is not listed here panics when a route is wired and is
	// refused when checked from code.
	Permissions Permissions
	Strict      bool

	// Decide, when set, sees every decision after roles and conditions and
	// may keep, allow or deny it. A callback that panics denies.
	Decide DecideFunc

	// OnDeny, when set, writes the response for a refused request instead of
	// the default 403.
	OnDeny func(w http.ResponseWriter, r *http.Request, c Check)

	// MaxRolesPerScope limits the custom roles of one organization, and of
	// the application. Default: 100.
	MaxRolesPerScope int
	// MaxGrantsPerRole limits the grants of one custom role. Default: 100.
	MaxGrantsPerRole int
	// MaxRolesPerUser limits the roles assigned to one user in one scope.
	// Default: 20.
	MaxRolesPerUser int

	// Storage replaces the storage backend's rbac store.
	Storage types.RBACStorage
}

func (c *Config) applyDefaults() {
	if c.MaxRolesPerScope <= 0 {
		c.MaxRolesPerScope = DefaultMaxRolesPerScope
	}
	if c.MaxGrantsPerRole <= 0 {
		c.MaxGrantsPerRole = DefaultMaxGrantsPerRole
	}
	if c.MaxRolesPerUser <= 0 {
		c.MaxRolesPerUser = DefaultMaxRolesPerUser
	}
}

// Grants of the roles that exist without any configuration.
var (
	superAdminGrants = []string{access.Wildcard, access.ReservedNamespace + ".*:*"}
	ownerGrants      = []string{access.Wildcard, access.ReservedNamespace + ".*:*"}
	// An organization admin may do anything with the application's own
	// resources and may see roles, but handing roles out stays with the
	// owner, as changing member roles does in the organization module.
	adminGrants = []string{access.Wildcard, access.PermRolesRead, access.PermAssignmentsRead}
)

// roleTable builds the roles defined in code, by scope and key, from the
// built-in ones and the configured ones.
func (c *Config) roleTable() (map[access.ScopeType]map[string]access.Role, error) {
	table := map[access.ScopeType]map[string]access.Role{
		access.ScopeGlobal: {
			access.RoleSuperAdmin: {
				Key:         access.RoleSuperAdmin,
				Name:        "Super admin",
				Description: "Every user with the super admin flag. Holds every permission everywhere.",
				Scope:       access.ScopeGlobal,
				Grants:      superAdminGrants,
			},
		},
		access.ScopeOrg: {},
	}
	if c.Organizations {
		table[access.ScopeOrg] = map[string]access.Role{
			access.RoleOwner:  {Key: access.RoleOwner, Name: "Owner", Description: "The organization's owner.", Scope: access.ScopeOrg, Grants: ownerGrants},
			access.RoleAdmin:  {Key: access.RoleAdmin, Name: "Admin", Description: "Organization members with the admin role.", Scope: access.ScopeOrg, Grants: adminGrants},
			access.RoleMember: {Key: access.RoleMember, Name: "Member", Description: "Every other organization member.", Scope: access.ScopeOrg, Grants: []string{}},
		}
	}

	seen := map[access.ScopeType]map[string]bool{access.ScopeGlobal: {}, access.ScopeOrg: {}}
	for _, role := range c.Roles {
		if !services.ValidRoleKey(role.Key) {
			return nil, fmt.Errorf("role key %q must be 1 to 64 lowercase letters, digits, '_' or '-'", role.Key)
		}
		if role.Key == access.RoleSuperAdmin {
			return nil, fmt.Errorf("role key %q is reserved for users with the super admin flag", role.Key)
		}
		grants, err := access.ParseSet(role.Grants)
		if err != nil {
			return nil, fmt.Errorf("role %q: %w", role.Key, err)
		}
		role.Grants = grants.Strings()
		if role.Name == "" {
			role.Name = role.Key
		}

		var scopes []access.ScopeType
		switch role.Scope {
		case access.ScopeAny:
			scopes = []access.ScopeType{access.ScopeGlobal}
			if c.Organizations {
				scopes = append(scopes, access.ScopeOrg)
			}
		case access.ScopeGlobal:
			scopes = []access.ScopeType{access.ScopeGlobal}
		case access.ScopeOrg:
			if !c.Organizations {
				return nil, fmt.Errorf("role %q is limited to organizations, but Organizations is off", role.Key)
			}
			scopes = []access.ScopeType{access.ScopeOrg}
		default:
			return nil, fmt.Errorf("role %q has unknown scope %q", role.Key, role.Scope)
		}
		for _, scope := range scopes {
			if seen[scope][role.Key] {
				return nil, fmt.Errorf("role %q is defined more than once for the %s scope", role.Key, scope)
			}
			seen[scope][role.Key] = true
			table[scope][role.Key] = role
		}
	}
	return table, nil
}

// declared returns the permissions listed in Permissions, validated.
func (c *Config) declared() ([]string, error) {
	var permissions []string
	for resource, actions := range c.Permissions {
		for _, action := range actions {
			permission := resource + ":" + action
			if err := validateHostPermission(permission); err != nil {
				return nil, err
			}
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

// validateHostPermission checks a permission declared by the application:
// well formed, and outside GoAuth's own namespace.
func validateHostPermission(permission string) error {
	if err := access.ValidatePermission(permission); err != nil {
		return err
	}
	resource, _, _ := cut(permission)
	if access.IsReserved(resource) {
		return fmt.Errorf("permission %q uses the reserved %q namespace", permission, access.ReservedNamespace)
	}
	return nil
}
