package services

//go:generate mockgen -destination=../../../mocks/mock_rbac_service.go -package=mocks github.com/bete7512/goauth/internal/modules/rbac/services AccessService,RoleService,AssignmentService

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Settings is the part of the module configuration the services need.
type Settings struct {
	// Organizations turns the organization scope on. Orgs and Members in
	// Stores must then be set.
	Organizations bool
	// Roles holds the roles defined in code, by scope and key. Membership
	// roles (owner, admin, member) live under the org scope.
	Roles map[access.ScopeType]map[string]access.Role
	// Decide, when set, sees every decision and may change it.
	Decide access.DecideFunc

	MaxRolesPerScope int
	MaxGrantsPerRole int
	MaxRolesPerUser  int
}

// Role returns the role defined in code for key in scope.
func (s Settings) Role(scope access.ScopeType, key string) (access.Role, bool) {
	role, ok := s.Roles[scope][key]
	return role, ok
}

// IsImplied reports whether key names a role that is never assigned in
// scope: the super admin flag, or an organization membership role.
func (s Settings) IsImplied(scope access.ScopeType, key string) bool {
	if key == access.RoleSuperAdmin {
		return true
	}
	if scope != access.ScopeOrg {
		return false
	}
	return key == access.RoleOwner || key == access.RoleAdmin || key == access.RoleMember
}

// Stores are the repositories the services read and write.
type Stores struct {
	RBAC    types.RBACStorage
	Users   models.UserRepository
	Orgs    models.OrganizationRepository
	Members models.OrganizationMemberRepository
}

// HeldRole is one role a user holds in a scope.
type HeldRole struct {
	Key         string
	Name        string
	Description string
	// Scope is where the role is held. A global role also applies inside
	// every organization.
	Scope access.ScopeType
	// System is true for roles defined in code.
	System bool
	// Implied is true for roles that come from the super admin flag or from
	// organization membership rather than from an assignment.
	Implied bool
	Grants  []string
}

// Holding is everything a user holds in one scope.
type Holding struct {
	UserID string
	Scope  access.Scope
	Roles  []HeldRole
	Grants access.Set
	// MembershipID is the user's current membership row in the organization
	// of the scope, or "" when there is none.
	MembershipID string
}

// RoleKeys returns the keys of the held roles, in the order they were found.
func (h *Holding) RoleKeys() []string {
	keys := make([]string, 0, len(h.Roles))
	for _, role := range h.Roles {
		keys = append(keys, role.Key)
	}
	return keys
}

func (h *Holding) add(role HeldRole) {
	h.Roles = append(h.Roles, role)
	h.Grants = append(h.Grants, access.ParseSetLenient(role.Grants)...)
}

// AuthorizeRequest is one decision to make.
type AuthorizeRequest struct {
	Principal  types.Principal
	UserID     string
	Permission string
	Scope      access.Scope
	Request    *http.Request
	// AllowIf conditions can grant a request the roles refused; OnlyIf
	// conditions can refuse one the roles granted.
	AllowIf []access.Condition
	OnlyIf  []access.Condition
}

// Verdict is the outcome of a decision.
type Verdict struct {
	Allowed bool
	Check   access.Check
	Holding *Holding
}

// AccessService answers what a user holds and whether a request is allowed.
type AccessService interface {
	// Holding returns the roles and grants userID holds in scope. A user who
	// does not exist or is not active holds nothing.
	Holding(ctx context.Context, userID string, scope access.Scope) (*Holding, *types.GoAuthError)
	// Authorize decides one request: roles first, then the request's own
	// conditions, then the Decide callback.
	Authorize(ctx context.Context, req AuthorizeRequest) (*Verdict, *types.GoAuthError)
}

type accessService struct {
	deps     config.ModuleDependencies
	stores   Stores
	settings Settings
}

// NewAccessService creates the service behind every permission check.
func NewAccessService(deps config.ModuleDependencies, stores Stores, settings Settings) *accessService {
	return &accessService{deps: deps, stores: stores, settings: settings}
}

func (s *accessService) Holding(ctx context.Context, userID string, scope access.Scope) (*Holding, *types.GoAuthError) {
	if authErr := checkScope(s.settings, scope); authErr != nil {
		return nil, authErr
	}
	holding := &Holding{UserID: userID, Scope: scope}
	if userID == "" {
		return holding, nil
	}
	if cached, ok := memoGet(ctx, userID, scope); ok {
		return cached, nil
	}

	user, err := s.stores.Users.FindByID(ctx, userID)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return nil, types.NewInternalError("failed to load user for authorization").Wrap(err)
	}
	if err != nil || user == nil || !user.Active {
		memoPut(ctx, holding)
		return holding, nil
	}
	if user.IsSuperAdmin {
		holding.add(s.heldSystemRole(access.ScopeGlobal, access.RoleSuperAdmin, true))
	}

	refs := []models.RoleScopeRef{{Type: models.RoleScopeGlobal}}
	if scope.IsOrg() {
		membership, authErr := s.membership(ctx, userID, scope.ID)
		if authErr != nil {
			return nil, authErr
		}
		if membership != nil {
			holding.MembershipID = membership.ID
			if _, ok := s.settings.Role(access.ScopeOrg, membership.Role); ok {
				holding.add(s.heldSystemRole(access.ScopeOrg, membership.Role, true))
			}
			refs = append(refs, models.RoleScopeRef{Type: models.RoleScopeOrg, ID: scope.ID})
		}
	}

	assignments, err := s.stores.RBAC.Assignments().ListByUser(ctx, userID, refs)
	if err != nil {
		return nil, types.NewInternalError("failed to load role assignments").Wrap(err)
	}
	if authErr := s.addAssigned(ctx, holding, assignments); authErr != nil {
		return nil, authErr
	}
	memoPut(ctx, holding)
	return holding, nil
}

// membership returns the user's current membership in an active
// organization, or nil. The organization the access token was issued for was
// already validated when the request was authenticated, so it is not loaded
// a second time.
func (s *accessService) membership(ctx context.Context, userID, orgID string) (*models.OrganizationMember, *types.GoAuthError) {
	member, err := s.stores.Members.FindByOrgAndUser(ctx, orgID, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && member == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load organization membership").Wrap(err)
	}
	if member.OrgID != orgID || member.UserID != userID {
		return nil, nil
	}
	if principal, ok := types.PrincipalFromContext(ctx); ok && principal.UserID == userID && principal.OrganizationID == orgID {
		return member, nil
	}
	org, err := s.stores.Orgs.FindByID(ctx, orgID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && org == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load organization").Wrap(err)
	}
	if !org.Active {
		return nil, nil
	}
	return member, nil
}

// addAssigned adds the roles the assignments name. An organization
// assignment only counts for the membership it was made for, and a role that
// is implied is never taken from an assignment row.
func (s *accessService) addAssigned(ctx context.Context, holding *Holding, assignments []*models.RoleAssignment) *types.GoAuthError {
	custom := map[access.ScopeType][]string{}
	for _, assignment := range assignments {
		scope, ok := s.assignmentScope(holding, assignment)
		if !ok || s.settings.IsImplied(scope, assignment.RoleKey) {
			continue
		}
		if role, defined := s.settings.Role(scope, assignment.RoleKey); defined {
			holding.add(HeldRole{Key: role.Key, Name: role.Name, Description: role.Description, Scope: scope, System: true, Grants: role.Grants})
			continue
		}
		custom[scope] = append(custom[scope], assignment.RoleKey)
	}
	for _, scope := range []access.ScopeType{access.ScopeGlobal, access.ScopeOrg} {
		keys := custom[scope]
		if len(keys) == 0 {
			continue
		}
		orgID := ""
		if scope == access.ScopeOrg {
			orgID = holding.Scope.ID
		}
		roles, err := s.stores.RBAC.Roles().FindByKeys(ctx, orgID, keys)
		if err != nil {
			return types.NewInternalError("failed to load roles").Wrap(err)
		}
		wanted := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			wanted[key] = struct{}{}
		}
		for _, role := range roles {
			// Compared again here: the database collation is not trusted to
			// keep keys and organizations apart.
			if _, ok := wanted[role.Key]; !ok || role.OrgID != orgID {
				continue
			}
			holding.add(HeldRole{Key: role.Key, Name: role.Name, Description: role.Description, Scope: scope, Grants: role.Grants})
		}
	}
	return nil
}

func (s *accessService) assignmentScope(holding *Holding, assignment *models.RoleAssignment) (access.ScopeType, bool) {
	if assignment.UserID != holding.UserID {
		return "", false
	}
	switch assignment.ScopeType {
	case models.RoleScopeGlobal:
		return access.ScopeGlobal, assignment.ScopeID == ""
	case models.RoleScopeOrg:
		current := holding.Scope.IsOrg() && assignment.ScopeID == holding.Scope.ID &&
			holding.MembershipID != "" && assignment.MembershipID == holding.MembershipID
		return access.ScopeOrg, current
	default:
		return "", false
	}
}

func (s *accessService) heldSystemRole(scope access.ScopeType, key string, implied bool) HeldRole {
	role, _ := s.settings.Role(scope, key)
	return HeldRole{Key: key, Name: role.Name, Description: role.Description, Scope: scope, System: true, Implied: implied, Grants: role.Grants}
}

func (s *accessService) Authorize(ctx context.Context, req AuthorizeRequest) (*Verdict, *types.GoAuthError) {
	if err := access.ValidatePermission(req.Permission); err != nil {
		return nil, types.NewInternalError("invalid permission in authorization check").Wrap(err)
	}
	holding, authErr := s.Holding(ctx, req.UserID, req.Scope)
	if authErr != nil {
		return nil, authErr
	}
	check := access.Check{
		Principal:  req.Principal,
		UserID:     req.UserID,
		Permission: req.Permission,
		Scope:      req.Scope.Type,
		OrgID:      req.Scope.OrgID(),
		Roles:      holding.RoleKeys(),
		Request:    req.Request,
	}
	check.Granted = holding.Grants.Allows(req.Permission)
	check.Allowed = check.Granted

	if !check.Allowed {
		for _, condition := range req.AllowIf {
			if s.holds(ctx, condition, check) {
				check.Allowed = true
				break
			}
		}
	}
	if check.Allowed {
		for _, condition := range req.OnlyIf {
			if !s.holds(ctx, condition, check) {
				check.Allowed = false
				break
			}
		}
	}
	if s.settings.Decide != nil {
		check.Allowed, check.Reason = s.decide(ctx, check).Apply(check.Allowed)
	}
	return &Verdict{Allowed: check.Allowed, Check: check, Holding: holding}, nil
}

// holds runs a condition of the application. A condition that panics counts
// as false, which refuses the request whichever way it was attached.
func (s *accessService) holds(ctx context.Context, condition access.Condition, check access.Check) (ok bool) {
	if condition == nil {
		return false
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.deps.Logger.Error("rbac: authorization condition panicked", "permission", check.Permission, "panic", fmt.Sprint(recovered))
			ok = false
		}
	}()
	return condition(ctx, check)
}

// decide runs the Decide callback. A callback that panics denies.
func (s *accessService) decide(ctx context.Context, check access.Check) (decision access.Decision) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.deps.Logger.Error("rbac: Decide callback panicked", "permission", check.Permission, "panic", fmt.Sprint(recovered))
			decision = access.Deny("")
		}
	}()
	return s.settings.Decide(ctx, check)
}

// checkScope refuses scopes the module is not configured for.
func checkScope(settings Settings, scope access.Scope) *types.GoAuthError {
	switch scope.Type {
	case access.ScopeGlobal:
		if scope.ID != "" {
			return types.NewRBACScopeUnavailableError("The global scope has no ID")
		}
		return nil
	case access.ScopeOrg:
		if !settings.Organizations {
			return types.NewRBACScopeUnavailableError("Organization roles are not enabled")
		}
		if scope.ID == "" {
			return types.NewRBACScopeUnavailableError("An organization is required")
		}
		return nil
	default:
		return types.NewRBACScopeUnavailableError("Unknown scope")
	}
}

// storageScope maps a scope to the values stored on assignments and roles.
func storageScope(scope access.Scope) (scopeType, scopeID string) {
	if scope.IsOrg() {
		return models.RoleScopeOrg, scope.ID
	}
	return models.RoleScopeGlobal, ""
}
