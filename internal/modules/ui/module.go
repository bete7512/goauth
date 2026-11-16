// Package ui is the server-rendered console: an admin console for super
// admins (users, audit log, roles) and, when enabled, a sign-in and account
// page for everyone else. Pages are html/template documents enhanced with
// htmx, which is embedded, so the console needs no build step and loads
// nothing from other origins.
package ui

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/internal/modules/audit"
	auditservices "github.com/bete7512/goauth/internal/modules/audit/services"
	"github.com/bete7512/goauth/internal/modules/core"
	coreservices "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/modules/idp"
	idpservices "github.com/bete7512/goauth/internal/modules/idp/services"
	"github.com/bete7512/goauth/internal/modules/invitation"
	invitationservices "github.com/bete7512/goauth/internal/modules/invitation/services"
	"github.com/bete7512/goauth/internal/modules/organization"
	orgservices "github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/modules/rbac"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed templates/*.html
	templateFS embed.FS

	//go:embed assets/*
	assetFS embed.FS
)

var _ config.Module = (*UIModule)(nil)

// UIModule is the ui module.
type UIModule struct {
	config *Config
	deps   config.ModuleDependencies

	base     string // BasePath + "/ui"
	pages    *pageSet
	assets   *assetSet
	admin    services.AdminService
	protect  *http.CrossOriginProtection
	notFound http.Handler
}

// New creates the ui module. Pass nil for the defaults: the admin console
// only, for super admins.
func New(cfg *Config) *UIModule {
	if cfg != nil {
		snapshot := *cfg
		cfg = &snapshot
	}
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.TrustedOrigins = append([]string(nil), cfg.TrustedOrigins...)
	cfg.applyDefaults()
	return &UIModule{config: cfg}
}

// Name returns the module identifier.
func (m *UIModule) Name() string { return string(types.UIModule) }

// Init checks that the application can serve a browser console and
// prepares templates and assets.
func (m *UIModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	if deps.Config == nil || !http_utils.CookiesEnabled(deps.Config.Security.AuthMode) {
		return config.ErrConfig("ui: the console signs users in with cookies, but Security.AuthMode does not allow them; use \"cookie\" or \"both\"")
	}
	if deps.Lookup == nil {
		return config.ErrConfig("ui: module lookup is unavailable")
	}
	if err := validatePath(m.config.Path); err != nil {
		return config.ErrConfig("ui: " + err.Error())
	}
	m.deps = deps
	m.base = strings.TrimRight(deps.Config.BasePath, "/") + "/ui"
	if m.config.Path != "" {
		m.base = m.config.Path
	}
	if cookiePath := deps.Config.Security.Session.Path; !cookieReaches(cookiePath, m.base) {
		return config.ErrConfig(fmt.Sprintf("ui: the console at %q would never receive the credential cookies, which Security.Session.Path limits to %q; set Path inside it or widen the cookie path", m.base, cookiePath))
	}

	m.protect = http.NewCrossOriginProtection()
	for _, origin := range m.config.TrustedOrigins {
		if err := m.protect.AddTrustedOrigin(origin); err != nil {
			return config.ErrConfig(fmt.Sprintf("ui: trusted origin %q: %v", origin, err))
		}
	}
	m.protect.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.renderError(w, r, http.StatusForbidden, "This request came from another site and was refused.")
	}))

	assets, err := loadAssets(assetFS)
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	m.assets = assets
	pages, err := loadPages(templateFS, m.funcs())
	if err != nil {
		return fmt.Errorf("ui: %w", err)
	}
	m.pages = pages
	m.admin = services.NewAdminService(deps, deps.Storage.Core().Users())
	m.notFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.renderError(w, r, http.StatusNotFound, "This page does not exist.")
	})
	deps.Logger.Info("UI module initialized", "path", m.base, "user_pages", m.config.UserPages)
	return nil
}

// Routes returns the console's pages. Every one is wrapped in
// cross-origin protection and security headers; all but the assets and the
// sign-in pages require a signed-in user, and the administration pages a
// super admin. A page for a module that is not registered answers with a
// page saying so, so links never break.
func (m *UIModule) Routes() []config.RouteInfo {
	get, post := http.MethodGet, http.MethodPost
	admin := m.adminOnly
	routes := []config.RouteInfo{
		m.route(types.RouteUIAsset, get, "/assets/{file}", m.serveAsset),
		m.route(types.RouteUIHome, get, "", m.home),
		m.route(types.RouteUILoginPage, get, "/login", m.loginPage),
		m.route(types.RouteUILogin, post, "/login", m.login),
		m.route(types.RouteUILoginTwoFactor, post, "/login/2fa", m.loginTwoFactor),
		m.route(types.RouteUILogout, post, "/logout", m.logout),

		// Users
		m.route(routeUsers, get, "/users", admin(m.users)),
		m.route(routeUserNew, get, "/users/new", admin(m.newUserPage)),
		m.route(routeUserCreate, post, "/users", admin(m.createUser)),
		m.route(routeUser, get, "/users/{id}", admin(m.user)),
		m.route(routeUserUpdate, post, "/users/{id}", admin(m.updateUser)),
		m.route(routeUserDelete, post, "/users/{id}/delete", admin(m.deleteUser)),
		m.route(routeUserSecurity, get, "/users/{id}/security", admin(m.userSecurity)),
		m.route(routeUserUnlock, post, "/users/{id}/unlock", admin(m.unlockUser)),
		m.route(routeUserSignOut, post, "/users/{id}/sign-out", admin(m.signOutUser)),
		m.route(routeUserPassword, post, "/users/{id}/password", admin(m.setUserPassword)),
		m.route(routeUserResetEmail, post, "/users/{id}/reset-email", admin(m.sendResetEmail)),
		m.route(routeUserVerifyEmail, post, "/users/{id}/verification-email", admin(m.sendVerificationEmail)),
		m.route(routeUserUnlink, post, "/users/{id}/accounts/{accountId}/unlink", admin(m.unlinkAccount)),
		m.route(routeUserSessionRevoke, post, "/users/{id}/sessions/{sessionId}/revoke", admin(m.revokeSession)),
		m.route(routeUserTwoFactorReset, post, "/users/{id}/2fa/reset", admin(m.resetTwoFactor)),
		m.route(routeUserPasskeyDelete, post, "/users/{id}/passkeys/{passkeyId}/delete", admin(m.deletePasskey)),
		m.route(routeUserAppRevoke, post, "/users/{id}/apps/{grantId}/revoke", admin(m.revokeApp)),
		m.route(routeUserAccess, get, "/users/{id}/access", admin(m.userAccess)),
		m.route(routeUserRoles, post, "/users/{id}/roles", admin(m.setUserRoles)),
		m.route(routeUserActivity, get, "/users/{id}/activity", admin(m.userActivity)),

		// Organizations
		m.route(routeOrgs, get, "/orgs", admin(m.orgs)),
		m.route(routeOrgNew, get, "/orgs/new", admin(m.newOrgPage)),
		m.route(routeOrgCreate, post, "/orgs", admin(m.createOrg)),
		m.route(routeOrg, get, "/orgs/{orgId}", admin(m.org)),
		m.route(routeOrgUpdate, post, "/orgs/{orgId}", admin(m.updateOrg)),
		m.route(routeOrgStatus, post, "/orgs/{orgId}/status", admin(m.setOrgStatus)),
		m.route(routeOrgDelete, post, "/orgs/{orgId}/delete", admin(m.deleteOrg)),
		m.route(routeOrgOwner, post, "/orgs/{orgId}/owner", admin(m.transferOrg)),
		m.route(routeOrgMembers, get, "/orgs/{orgId}/members", admin(m.orgMembers)),
		m.route(routeOrgMemberAdd, post, "/orgs/{orgId}/members", admin(m.addOrgMember)),
		m.route(routeOrgMember, get, "/orgs/{orgId}/members/{userId}", admin(m.orgMember)),
		m.route(routeOrgMemberRole, post, "/orgs/{orgId}/members/{userId}/role", admin(m.changeOrgMemberRole)),
		m.route(routeOrgMemberRemove, post, "/orgs/{orgId}/members/{userId}/remove", admin(m.removeOrgMember)),
		m.route(routeOrgMemberRoles, post, "/orgs/{orgId}/members/{userId}/roles", admin(m.setOrgMemberRoles)),
		m.route(routeOrgInvitations, get, "/orgs/{orgId}/invitations", admin(m.orgInvitations)),
		m.route(routeOrgInvitationCancel, post, "/orgs/{orgId}/invitations/{invId}/cancel", admin(m.cancelOrgInvitation)),
		m.route(routeOrgRoles, get, "/orgs/{orgId}/roles", admin(m.roles)),
		m.route(routeOrgRoleCreate, post, "/orgs/{orgId}/roles", admin(m.createRole)),
		m.route(routeOrgRole, get, "/orgs/{orgId}/roles/{roleKey}", admin(m.role)),
		m.route(routeOrgRoleUpdate, post, "/orgs/{orgId}/roles/{roleKey}", admin(m.updateRole)),
		m.route(routeOrgRoleDelete, post, "/orgs/{orgId}/roles/{roleKey}/delete", admin(m.deleteRole)),

		// Platform invitations
		m.route(routeInvitations, get, "/invitations", admin(m.invitations)),
		m.route(routeInvitationSend, post, "/invitations", admin(m.sendInvitation)),
		m.route(routeInvitationCancel, post, "/invitations/{invId}/cancel", admin(m.cancelInvitation)),

		// Roles and permissions
		m.route(routeRoles, get, "/roles", admin(m.roles)),
		m.route(routeRoleCreate, post, "/roles", admin(m.createRole)),
		m.route(routeRole, get, "/roles/{roleKey}", admin(m.role)),
		m.route(routeRoleUpdate, post, "/roles/{roleKey}", admin(m.updateRole)),
		m.route(routeRoleDelete, post, "/roles/{roleKey}/delete", admin(m.deleteRole)),
		m.route(routePermissions, get, "/permissions", admin(m.permissions)),

		// Applications (identity provider clients)
		m.route(routeClients, get, "/clients", admin(m.clients)),
		m.route(routeClientNew, get, "/clients/new", admin(m.newClientPage)),
		m.route(routeClientCreate, post, "/clients", admin(m.createClient)),
		m.route(routeClient, get, "/clients/{clientId}", admin(m.client)),
		m.route(routeClientUpdate, post, "/clients/{clientId}", admin(m.updateClient)),
		m.route(routeClientRotate, post, "/clients/{clientId}/rotate", admin(m.rotateClient)),
		m.route(routeClientDelete, post, "/clients/{clientId}/delete", admin(m.deleteClient)),

		// Activity and system
		m.route(routeAudit, get, "/audit", admin(m.auditLog)),
		m.route(routeAuditCleanup, post, "/audit/cleanup", admin(m.cleanupAudit)),
		m.route(routeSettings, get, "/settings", admin(m.settings)),
	}
	if m.config.UserPages {
		routes = append(routes, m.route(types.RouteUIAccount, get, "/account", m.signedIn(m.account)))
	}
	return routes
}

// route mounts a page. path is relative to the console root: under
// BasePath + "/ui" by default, or at Config.Path as an absolute route.
func (m *UIModule) route(name types.RouteName, method, path string, handler http.HandlerFunc) config.RouteInfo {
	mount := "/ui"
	if m.config.Path != "" {
		mount = m.config.Path
	}
	return config.RouteInfo{Name: string(name), Method: method, Path: mount + path, Absolute: m.config.Path != "", Handler: func(w http.ResponseWriter, r *http.Request) {
		if m.protect == nil {
			http.Error(w, "console unavailable", http.StatusServiceUnavailable)
			return
		}
		m.protect.Handler(m.secure(handler)).ServeHTTP(w, r)
	}}
}

// Middlewares returns nil: the console guards its own pages.
func (m *UIModule) Middlewares() []config.MiddlewareConfig { return nil }

// RegisterHooks returns nil: the console only reads.
func (m *UIModule) RegisterHooks(types.EventBus) error { return nil }

// Dependencies returns core. Audit and rbac pages appear when those modules
// are registered.
func (m *UIModule) Dependencies() []string { return []string{string(types.CoreModule)} }

// OpenAPISpecs returns the module's OpenAPI document, which lists no paths:
// the console serves HTML, not an API.
func (m *UIModule) OpenAPISpecs() []byte { return openapiSpec }

// Migrations returns nil: the console has no tables.
func (m *UIModule) Migrations() types.ModuleMigrations { return types.ModuleMigrations{} }

// --- collaborators, looked up when a request needs them ---

func (m *UIModule) strategy() config.Module {
	name := string(types.StatelessModule)
	if m.deps.Config.Security.AuthStrategy == types.StrategySession {
		name = string(types.SessionModule)
	}
	module, _ := m.deps.Lookup(name)
	return module
}

func (m *UIModule) auditService() auditservices.AuditService {
	module, ok := m.deps.Lookup(string(types.AuditModule))
	if !ok {
		return nil
	}
	auditModule, ok := module.(*audit.AuditModule)
	if !ok {
		return nil
	}
	return audit.Service(auditModule)
}

func (m *UIModule) rbacModule() (*rbac.RBACModule, rbac.Internals, bool) {
	module, ok := m.deps.Lookup(string(types.RBACModule))
	if !ok {
		return nil, rbac.Internals{}, false
	}
	rbacModule, ok := module.(*rbac.RBACModule)
	if !ok {
		return nil, rbac.Internals{}, false
	}
	internals, ready := rbac.ServicesOf(rbacModule)
	return rbacModule, internals, ready
}

func (m *UIModule) twoFactor() types.TwoFactorLoginVerifier {
	module, ok := m.deps.Lookup(string(types.TwoFactorModule))
	if !ok {
		return nil
	}
	verifier, _ := module.(types.TwoFactorLoginVerifier)
	return verifier
}

// lookup returns a registered module of type T, or false.
func lookup[T any](m *UIModule, name types.ModuleName) (T, bool) {
	var zero T
	module, ok := m.deps.Lookup(string(name))
	if !ok {
		return zero, false
	}
	typed, ok := module.(T)
	return typed, ok
}

func (m *UIModule) orgAdmin() orgservices.AdminService {
	module, ok := lookup[*organization.OrganizationModule](m, types.OrganizationModule)
	if !ok {
		return nil
	}
	return organization.AdminServiceOf(module)
}

func (m *UIModule) invitationService() invitationservices.InvitationService {
	module, ok := lookup[*invitation.InvitationModule](m, types.InvitationModule)
	if !ok {
		return nil
	}
	return invitation.ServiceOf(module)
}

func (m *UIModule) idpService() idpservices.IDPService {
	module, ok := lookup[*idp.IDPModule](m, types.IDPModule)
	if !ok {
		return nil
	}
	return idp.ServiceOf(module)
}

func (m *UIModule) coreService() coreservices.CoreService {
	module, ok := lookup[*core.CoreModule](m, types.CoreModule)
	if !ok {
		return nil
	}
	return core.ServiceOf(module)
}
