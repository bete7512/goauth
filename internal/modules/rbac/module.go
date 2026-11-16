// Package rbac is the role-based access control module: roles, who holds
// them, and the checks an application makes against them on its routes and
// in its services.
package rbac

import (
	"context"
	"embed"
	"maps"
	"net/http"
	"sync/atomic"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/handlers"
	"github.com/bete7512/goauth/internal/modules/rbac/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed migrations
	migrationFS embed.FS
)

var _ config.Module = (*RBACModule)(nil)

// RBACModule is the rbac module. Besides the module contract it carries the
// API an application calls: Require and Resource to guard routes, Can and
// Check to decide in code.
type RBACModule struct {
	config    *Config
	configErr error
	roleTable map[access.ScopeType]map[string]access.Role
	catalog   *catalog

	deps        config.ModuleDependencies
	access      services.AccessService
	roles       services.RoleService
	assignments services.AssignmentService
	handler     *handlers.Handler
	ready       atomic.Bool
}

// New creates the rbac module. Pass nil for the defaults: permissions
// declared where they are used, application-wide roles only.
//
// A mistake in the configuration (a malformed role, a duplicate key) is
// reported by Init, which Auth.Initialize surfaces.
func New(cfg *Config) *RBACModule {
	if cfg != nil {
		snapshot := *cfg
		cfg = &snapshot
	}
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.Roles = append([]Role(nil), cfg.Roles...)
	cfg.Permissions = maps.Clone(cfg.Permissions)
	cfg.applyDefaults()

	m := &RBACModule{config: cfg, catalog: newCatalog()}
	for _, own := range ownPermissions {
		_ = m.catalog.declare(own.Permission, own.Description)
	}
	m.roleTable, m.configErr = cfg.roleTable()
	declared, err := cfg.declared()
	if err != nil && m.configErr == nil {
		m.configErr = err
	}
	for _, permission := range declared {
		_ = m.catalog.declare(permission, "")
	}
	if cfg.Strict {
		m.catalog.seal()
	}
	return m
}

// Name returns the module identifier.
func (m *RBACModule) Name() string {
	return string(types.RBACModule)
}

// Init wires the module to storage and builds its services.
func (m *RBACModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	if m.configErr != nil {
		return config.ErrConfig("rbac: " + m.configErr.Error())
	}
	m.deps = deps

	store := m.config.Storage
	if store == nil {
		store = deps.Storage.RBAC()
	}
	if store == nil {
		return config.ErrConfig("rbac: storage is not available; use a storage backend that provides RBAC() or set Config.Storage")
	}
	stores := services.Stores{RBAC: store, Users: deps.Storage.Core().Users()}
	if m.config.Organizations {
		orgStorage := deps.Storage.Organization()
		if orgStorage == nil {
			return config.ErrConfig("rbac: Organizations is on but organization storage is not available")
		}
		stores.Orgs = orgStorage.Organizations()
		stores.Members = orgStorage.Members()
	}

	settings := services.Settings{
		Organizations:    m.config.Organizations,
		Roles:            m.roleTable,
		Decide:           m.config.Decide,
		MaxRolesPerScope: m.config.MaxRolesPerScope,
		MaxGrantsPerRole: m.config.MaxGrantsPerRole,
		MaxRolesPerUser:  m.config.MaxRolesPerUser,
	}
	accessService := services.NewAccessService(deps, stores, settings)
	m.access = accessService
	m.roles = services.NewRoleService(deps, stores, settings, accessService)
	m.assignments = services.NewAssignmentService(deps, stores, settings, accessService)
	m.handler = handlers.NewHandler(deps, m.access, m.roles, m.assignments, m.catalogDTO, m.config.Organizations)

	m.ready.Store(true)
	deps.Logger.Info("RBAC module initialized", "organizations", m.config.Organizations, "strict", m.config.Strict)
	return nil
}

// Routes returns the role and assignment endpoints. The organization routes
// exist only when Organizations is on.
func (m *RBACModule) Routes() []config.RouteInfo {
	auth := []types.MiddlewareName{types.MiddlewareAuth}
	routes := []config.RouteInfo{
		{Name: string(types.RouteRBACPermissions), Path: "/rbac/permissions", Method: http.MethodGet, Handler: m.handler.ListPermissions, Middlewares: auth},
		{Name: string(types.RouteRBACMyPermissions), Path: "/me/permissions", Method: http.MethodGet, Handler: m.handler.MyPermissions, Middlewares: auth},

		{Name: string(types.RouteRBACListRoles), Path: "/rbac/roles", Method: http.MethodGet, Handler: m.handler.ListRoles, Middlewares: auth},
		{Name: string(types.RouteRBACCreateRole), Path: "/rbac/roles", Method: http.MethodPost, Handler: m.handler.CreateRole, Middlewares: auth},
		{Name: string(types.RouteRBACGetRole), Path: "/rbac/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodGet, Handler: m.handler.GetRole, Middlewares: auth},
		{Name: string(types.RouteRBACUpdateRole), Path: "/rbac/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodPut, Handler: m.handler.UpdateRole, Middlewares: auth},
		{Name: string(types.RouteRBACDeleteRole), Path: "/rbac/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodDelete, Handler: m.handler.DeleteRole, Middlewares: auth},
		{Name: string(types.RouteRBACGetUserRoles), Path: "/rbac/users/{" + handlers.ParamUserID + "}/roles", Method: http.MethodGet, Handler: m.handler.GetUserRoles, Middlewares: auth},
		{Name: string(types.RouteRBACSetUserRoles), Path: "/rbac/users/{" + handlers.ParamUserID + "}/roles", Method: http.MethodPut, Handler: m.handler.SetUserRoles, Middlewares: auth},
		{Name: string(types.RouteRBACListAssignments), Path: "/rbac/assignments", Method: http.MethodGet, Handler: m.handler.ListAssignments, Middlewares: auth},
	}
	if !m.config.Organizations {
		return routes
	}
	org := "/org/{" + handlers.ParamOrgID + "}"
	return append(routes,
		config.RouteInfo{Name: string(types.RouteRBACOrgListRoles), Path: org + "/roles", Method: http.MethodGet, Handler: m.handler.ListRoles, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgCreateRole), Path: org + "/roles", Method: http.MethodPost, Handler: m.handler.CreateRole, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgGetRole), Path: org + "/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodGet, Handler: m.handler.GetRole, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgUpdateRole), Path: org + "/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodPut, Handler: m.handler.UpdateRole, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgDeleteRole), Path: org + "/roles/{" + handlers.ParamRoleKey + "}", Method: http.MethodDelete, Handler: m.handler.DeleteRole, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgGetMemberRoles), Path: org + "/members/{" + handlers.ParamUserID + "}/roles", Method: http.MethodGet, Handler: m.handler.GetUserRoles, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgSetMemberRoles), Path: org + "/members/{" + handlers.ParamUserID + "}/roles", Method: http.MethodPut, Handler: m.handler.SetUserRoles, Middlewares: auth},
		config.RouteInfo{Name: string(types.RouteRBACOrgListAssignments), Path: org + "/role-assignments", Method: http.MethodGet, Handler: m.handler.ListAssignments, Middlewares: auth},
	)
}

// Middlewares returns nil: the module's guards are attached by the
// application with Require and Resource, not registered by name.
func (m *RBACModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

// RegisterHooks removes assignments that can no longer apply: those of a
// deleted user, of a member who left an organization, and of a deleted
// organization. This is housekeeping. A check never relies on it: a user
// who does not exist holds nothing, and an organization assignment only
// counts for the membership it was made for.
func (m *RBACModule) RegisterHooks(events types.EventBus) error {
	if events == nil {
		return nil
	}
	events.Subscribe(types.EventAdminUserDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[map[string]interface{}](event)
		if !ok || m.assignments == nil {
			return nil
		}
		userID, _ := data["target_id"].(string)
		if err := m.assignments.RemoveUser(ctx, userID); err != nil {
			m.deps.Logger.Warnf("rbac: failed to remove the role assignments of deleted user %s: %v", userID, err)
		}
		return nil
	}))
	if !m.config.Organizations {
		return nil
	}
	events.Subscribe(types.EventOrgMemberRemoved, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[*types.OrgMemberEventData](event)
		if !ok || data == nil || m.assignments == nil {
			return nil
		}
		if err := m.assignments.RemoveMember(ctx, data.OrgID, data.UserID); err != nil {
			m.deps.Logger.Warnf("rbac: failed to remove the role assignments of former member %s in organization %s: %v", data.UserID, data.OrgID, err)
		}
		return nil
	}))
	events.Subscribe(types.EventOrgDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[*types.OrgEventData](event)
		if !ok || data == nil || data.Organization == nil || m.roles == nil {
			return nil
		}
		if err := m.roles.RemoveOrganization(ctx, data.Organization.ID); err != nil {
			m.deps.Logger.Warnf("rbac: failed to remove the roles of deleted organization %s: %v", data.Organization.ID, err)
		}
		return nil
	}))
	return nil
}

// Dependencies returns the modules that must be registered: core, and the
// organization module when Organizations is on.
func (m *RBACModule) Dependencies() []string {
	dependencies := []string{string(types.CoreModule)}
	if m.config.Organizations {
		dependencies = append(dependencies, string(types.OrganizationModule))
	}
	return dependencies
}

// OpenAPISpecs returns the module's OpenAPI document.
func (m *RBACModule) OpenAPISpecs() []byte {
	return openapiSpec
}

// Migrations returns the module's SQL migrations.
func (m *RBACModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}

func (m *RBACModule) catalogDTO() []dto.PermissionDTO {
	entries := m.catalog.list()
	out := make([]dto.PermissionDTO, 0, len(entries))
	for _, entry := range entries {
		out = append(out, dto.PermissionDTO{Permission: entry.Permission, Description: entry.Description})
	}
	return out
}

// Internals are the rbac services, for the ui module's pages.
type Internals struct {
	// Organizations is true when roles can be held inside organizations.
	Organizations bool
	Access        services.AccessService
	Roles         services.RoleService
	Assignments   services.AssignmentService
}

// ServicesOf returns the services of an initialized rbac module and false
// before Init. It is a function rather than a method so that it does not
// appear on the public rbac.Module type.
func ServicesOf(m *RBACModule) (Internals, bool) {
	if m == nil || !m.ready.Load() {
		return Internals{}, false
	}
	return Internals{Organizations: m.config.Organizations, Access: m.access, Roles: m.roles, Assignments: m.assignments}, true
}
