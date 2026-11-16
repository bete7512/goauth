package rbac

import (
	"context"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Authorizer is what application code depends on to ask "may the caller do
// this". *RBACModule implements it; Fixed gives a stand-in for unit tests.
type Authorizer interface {
	// Can reports whether the caller holds permission. It is false when the
	// request is not authenticated or the answer could not be worked out.
	Can(ctx context.Context, permission string, opts ...Option) bool
	// Check returns nil when the caller holds permission, and otherwise a
	// *types.GoAuthError saying why: not signed in, permission missing, or
	// the lookup failed.
	Check(ctx context.Context, permission string, opts ...Option) error
}

var _ Authorizer = (*RBACModule)(nil)

// Define declares a permission the application checks and returns it, so it
// can be kept in a variable. Declaring is optional: Require and Resource do
// it for the permissions they guard. It is useful for a permission that is
// only checked from code, so that it shows up in the catalog before its
// first use, and for attaching a description.
//
// Define panics on a malformed permission, on one in GoAuth's own
// namespace, and in Strict mode on one that is not listed in the
// configuration.
func (m *RBACModule) Define(permission string, description ...string) string {
	m.mustDeclare(permission, strings.Join(description, " "))
	return permission
}

// Catalog returns the permissions declared so far, sorted.
func (m *RBACModule) Catalog() []PermissionInfo {
	return m.catalog.list()
}

// Can reports whether the caller in ctx holds permission. Without an option
// the check runs in the organization the caller is signed in to, or
// application-wide when there is none.
func (m *RBACModule) Can(ctx context.Context, permission string, opts ...Option) bool {
	return m.can(ctx, subject{}, permission, opts)
}

// Check is Can with the reason: nil when allowed, a *types.GoAuthError
// otherwise.
func (m *RBACModule) Check(ctx context.Context, permission string, opts ...Option) error {
	return m.check(ctx, subject{}, permission, opts)
}

// Permissions returns the grants the caller in ctx holds, as sorted patterns
// such as "invoice:*".
func (m *RBACModule) Permissions(ctx context.Context, opts ...Option) ([]string, error) {
	return m.permissions(ctx, subject{}, opts)
}

// TeamsWhere says in which teams of an organization the caller in ctx may
// do permission, for routes that list team resources (rbac Config.Teams).
// all is true when the permission holds in the whole organization, through
// an organization or application-wide role; ids is then nil. Otherwise ids
// are the teams where it holds through a role on the team or on a team above
// it, or a lead's membership, each checked as InTeam would.
func (m *RBACModule) TeamsWhere(ctx context.Context, orgID, permission string) (ids []string, all bool, err error) {
	return m.teamsWhere(ctx, subject{}, orgID, permission)
}

// For returns a view of the module that decides for userID instead of the
// caller in the context. It is for code that runs outside a request: a
// worker, a scheduled job, a command. Its checks run application-wide
// unless InOrg says otherwise.
func (m *RBACModule) For(userID string) *Subject {
	return &Subject{module: m, userID: userID}
}

// Subject decides for one named user. Get one from For.
type Subject struct {
	module *RBACModule
	userID string
}

var _ Authorizer = (*Subject)(nil)

// Can reports whether the user holds permission.
func (s *Subject) Can(ctx context.Context, permission string, opts ...Option) bool {
	return s.module.can(ctx, subject{userID: s.userID, explicit: true}, permission, opts)
}

// Check is Can with the reason.
func (s *Subject) Check(ctx context.Context, permission string, opts ...Option) error {
	return s.module.check(ctx, subject{userID: s.userID, explicit: true}, permission, opts)
}

// Permissions returns the grants the user holds, as sorted patterns.
func (s *Subject) Permissions(ctx context.Context, opts ...Option) ([]string, error) {
	return s.module.permissions(ctx, subject{userID: s.userID, explicit: true}, opts)
}

// Assign gives userID a role from the application's own code, for example
// when a user signs up. It is trusted: no permission is needed and the role
// may grant anything. The role is assigned application-wide unless InOrg
// names an organization. Assigning a role the user already holds does nothing.
func (m *RBACModule) Assign(ctx context.Context, userID, role string, opts ...Option) error {
	scope, authErr := m.manageScope(opts)
	if authErr != nil {
		return authErr
	}
	if authErr := m.assignments.Assign(ctx, nil, userID, scope, role); authErr != nil {
		return authErr
	}
	return nil
}

// Revoke takes a role away from userID from the application's own code.
// Revoking a role the user does not hold does nothing.
func (m *RBACModule) Revoke(ctx context.Context, userID, role string, opts ...Option) error {
	scope, authErr := m.manageScope(opts)
	if authErr != nil {
		return authErr
	}
	if authErr := m.assignments.Revoke(ctx, nil, userID, scope, role); authErr != nil {
		return authErr
	}
	return nil
}

// subject says whose permissions a check is about: the caller in the
// context, or a user named explicitly.
type subject struct {
	userID   string
	explicit bool
}

func (m *RBACModule) can(ctx context.Context, who subject, permission string, opts []Option) bool {
	verdict, authErr := m.evaluate(ctx, nil, who, permission, opts)
	if authErr != nil {
		if authErr.StatusCode >= http.StatusInternalServerError {
			m.logError("rbac: check failed", authErr, permission)
		}
		return false
	}
	return verdict.Allowed
}

func (m *RBACModule) check(ctx context.Context, who subject, permission string, opts []Option) error {
	verdict, authErr := m.evaluate(ctx, nil, who, permission, opts)
	if authErr != nil {
		return authErr
	}
	if !verdict.Allowed {
		return services.DeniedError(verdict.Check)
	}
	return nil
}

func (m *RBACModule) permissions(ctx context.Context, who subject, opts []Option) ([]string, error) {
	if !m.ready.Load() {
		return nil, notReady()
	}
	userID, principal, authErr := m.identify(ctx, who)
	if authErr != nil {
		return nil, authErr
	}
	scope, authErr := m.resolveScope(principal, nil, who.explicit, collect(opts))
	if authErr != nil {
		return nil, authErr
	}
	holding, authErr := m.access.Holding(ctx, userID, scope)
	if authErr != nil {
		return nil, authErr
	}
	return holding.Grants.Strings(), nil
}

// evaluate makes one decision. r is the request being guarded, or nil when
// the check comes from code.
func (m *RBACModule) evaluate(ctx context.Context, r *http.Request, who subject, permission string, opts []Option) (*services.Verdict, *types.GoAuthError) {
	if !m.ready.Load() {
		return nil, notReady()
	}
	userID, principal, authErr := m.identify(ctx, who)
	if authErr != nil {
		return nil, authErr
	}
	if err := access.ValidatePermission(permission); err != nil {
		return nil, types.NewInternalError("invalid permission in authorization check").Wrap(err)
	}
	if !m.catalog.allows(permission) {
		return nil, types.NewInternalError("permission is not listed in the rbac configuration: " + permission)
	}
	options := collect(opts)
	scope, authErr := m.resolveScope(principal, r, who.explicit, options)
	if authErr != nil {
		return nil, authErr
	}
	return m.access.Authorize(ctx, services.AuthorizeRequest{
		Principal:  principal,
		UserID:     userID,
		Permission: permission,
		Scope:      scope,
		Request:    r,
		AllowIf:    options.allowIf,
		OnlyIf:     options.onlyIf,
	})
}

// identify returns the user a check is about and, when that user is the
// caller, the caller's principal.
func (m *RBACModule) identify(ctx context.Context, who subject) (string, types.Principal, *types.GoAuthError) {
	principal, _ := types.PrincipalFromContext(ctx)
	if !who.explicit {
		if principal.UserID == "" {
			return "", types.Principal{}, types.NewUnauthorizedError()
		}
		return principal.UserID, principal, nil
	}
	if who.userID == "" {
		return "", types.Principal{}, types.NewUnauthorizedError()
	}
	if principal.UserID != who.userID {
		principal = types.Principal{}
	}
	return who.userID, principal, nil
}

// manageScope is the scope of a change made from code: application-wide
// unless an option names an organization.
func (m *RBACModule) manageScope(opts []Option) (access.Scope, *types.GoAuthError) {
	if !m.ready.Load() {
		return access.Scope{}, notReady()
	}
	return m.resolveScope(types.Principal{}, nil, true, collect(opts))
}

func (m *RBACModule) mustDeclare(permission, description string) {
	if err := validateHostPermission(permission); err != nil {
		panic("rbac: " + err.Error())
	}
	if err := m.catalog.declare(permission, description); err != nil {
		panic("rbac: " + err.Error())
	}
}

func (m *RBACModule) logError(message string, authErr *types.GoAuthError, permission string) {
	if m.deps.Logger != nil {
		m.deps.Logger.Error(message, "permission", permission, "error", authErr.Error())
	}
}

func notReady() *types.GoAuthError {
	return &types.GoAuthError{
		Code:       types.ErrInternalError,
		Message:    "Authorization is unavailable: the rbac module is not initialized",
		StatusCode: http.StatusServiceUnavailable,
	}
}

// Fixed returns an Authorizer that allows exactly the given grants to every
// caller and does no lookups. It is meant for an application's unit tests,
// in place of the module. It panics on a malformed grant.
func Fixed(grants ...string) Authorizer {
	set, err := access.ParseSet(grants)
	if err != nil {
		panic("rbac: " + err.Error())
	}
	return fixed{grants: set}
}

type fixed struct{ grants access.Set }

func (f fixed) Can(_ context.Context, permission string, _ ...Option) bool {
	return f.grants.Allows(permission)
}

func (f fixed) Check(_ context.Context, permission string, _ ...Option) error {
	if f.grants.Allows(permission) {
		return nil
	}
	return types.NewRBACPermissionDeniedError("Missing permission: " + permission)
}

// TeamsWhere is Module.TeamsWhere for this user.
func (s *Subject) TeamsWhere(ctx context.Context, orgID, permission string) ([]string, bool, error) {
	return s.module.teamsWhere(ctx, subject{userID: s.userID, explicit: true}, orgID, permission)
}

func (m *RBACModule) teamsWhere(ctx context.Context, who subject, orgID, permission string) ([]string, bool, error) {
	if !m.ready.Load() {
		return nil, false, notReady()
	}
	if !m.config.Teams {
		return nil, false, types.NewRBACScopeUnavailableError("Team roles are not enabled")
	}
	ctx = services.WithMemo(ctx)
	verdict, authErr := m.evaluate(ctx, nil, who, permission, []Option{InOrg(orgID)})
	if authErr != nil {
		return nil, false, authErr
	}
	if verdict.Allowed {
		return nil, true, nil
	}
	userID, _, authErr := m.identify(ctx, who)
	if authErr != nil {
		return nil, false, authErr
	}
	opts := models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: maxTeamsScanned, SortField: "path", SortDir: "asc"}}
	opts.Normalize(maxTeamsScanned)
	teams, _, err := m.stores.Teams.List(ctx, orgID, opts)
	if err != nil {
		return nil, false, types.NewInternalError("failed to list teams").Wrap(err)
	}
	// Teams where the user holds anything at all: a membership or a team
	// role. Only those and the teams beneath them can allow more than the
	// organization did.
	roots := map[string]bool{}
	memberships, err := m.stores.TeamMembers.ListByUser(ctx, orgID, userID)
	if err != nil {
		return nil, false, types.NewInternalError("failed to load team memberships").Wrap(err)
	}
	for _, membership := range memberships {
		roots[membership.TeamID] = true
	}
	refs := make([]models.RoleScopeRef, 0, len(teams))
	for _, team := range teams {
		refs = append(refs, models.RoleScopeRef{Type: models.RoleScopeTeam, ID: team.ID})
	}
	assignments, err := m.stores.RBAC.Assignments().ListByUser(ctx, userID, refs)
	if err != nil {
		return nil, false, types.NewInternalError("failed to load role assignments").Wrap(err)
	}
	for _, assignment := range assignments {
		roots[assignment.ScopeID] = true
	}
	var allowed []string
	for _, team := range teams {
		reachable := false
		for _, id := range team.AncestorIDs() {
			if roots[id] {
				reachable = true
				break
			}
		}
		if !reachable {
			continue
		}
		verdict, authErr := m.evaluate(ctx, nil, who, permission, []Option{InTeam(team.ID)})
		if authErr != nil {
			return nil, false, authErr
		}
		if verdict.Allowed {
			allowed = append(allowed, team.ID)
		}
	}
	return allowed, false, nil
}

// maxTeamsScanned bounds the teams TeamsWhere looks at in one organization.
const maxTeamsScanned = 1000
