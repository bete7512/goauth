package rbac

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
)

// PermissionInfo is one entry of the permission catalog: a permission the
// application checks somewhere, and what it is for.
type PermissionInfo struct {
	Permission  string
	Description string
}

// catalog is the set of permissions the application has declared. It fills
// itself: Require, Resource and Define add to it as routes are wired. It is
// what a role editor offers, and in Strict mode it is fixed up front.
type catalog struct {
	mu      sync.RWMutex
	entries map[string]PermissionInfo
	strict  bool
}

func newCatalog() *catalog {
	return &catalog{entries: map[string]PermissionInfo{}}
}

// declare records a permission. In strict mode a permission that was not
// listed in the configuration is refused.
func (c *catalog) declare(permission, description string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, known := c.entries[permission]
	if !known && c.strict {
		return fmt.Errorf("permission %q is not listed in Config.Permissions (Strict is on)", permission)
	}
	if description == "" {
		description = existing.Description
	}
	c.entries[permission] = PermissionInfo{Permission: permission, Description: description}
	return nil
}

// seal turns strict mode on: from now on only known permissions are accepted.
func (c *catalog) seal() {
	c.mu.Lock()
	c.strict = true
	c.mu.Unlock()
}

// allows reports whether a permission may be checked: always, unless strict
// mode is on and the permission was never declared.
func (c *catalog) allows(permission string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.strict {
		return true
	}
	_, known := c.entries[permission]
	return known
}

func (c *catalog) list() []PermissionInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]PermissionInfo, 0, len(c.entries))
	for _, entry := range c.entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Permission < out[j].Permission })
	return out
}

func cut(permission string) (resource, action string, ok bool) {
	return strings.Cut(permission, ":")
}

// ownPermissions are GoAuth's permissions for managing roles. They are in
// every catalog so that a role editor can offer them.
var ownPermissions = []PermissionInfo{
	{Permission: access.PermRolesRead, Description: "See roles and the permission catalog"},
	{Permission: access.PermRolesWrite, Description: "Create, change and delete roles"},
	{Permission: access.PermAssignmentsRead, Description: "See which roles other users hold"},
	{Permission: access.PermAssignmentsWrite, Description: "Give roles to users and take them away"},
}
