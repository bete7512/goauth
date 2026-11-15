package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// UserRoles is what one user holds in a scope: the roles, where each comes
// from, and the grants they add up to.
type UserRoles struct {
	UserID string
	Scope  access.Scope
	Roles  []HeldRole
	Grants []string
}

// AssignmentService manages which user holds which role in a scope.
type AssignmentService interface {
	// Get returns what userID holds in scope. Users may read their own
	// roles; reading someone else's needs the assignments read permission.
	Get(ctx context.Context, actor *Actor, userID string, scope access.Scope) (*UserRoles, *types.GoAuthError)
	// Set makes keys the complete list of roles assigned to userID in scope.
	// Roles that are implied are not part of the list and are not touched.
	Set(ctx context.Context, actor *Actor, userID string, scope access.Scope, keys []string) (*UserRoles, *types.GoAuthError)
	Assign(ctx context.Context, actor *Actor, userID string, scope access.Scope, key string) *types.GoAuthError
	Revoke(ctx context.Context, actor *Actor, userID string, scope access.Scope, key string) *types.GoAuthError
	List(ctx context.Context, actor *Actor, scope access.Scope, opts models.RoleAssignmentListOpts) ([]*models.RoleAssignment, int64, *types.GoAuthError)
	// RemoveUser deletes every assignment of a user who no longer exists.
	RemoveUser(ctx context.Context, userID string) error
	// RemoveMember deletes the assignments of a user who left an organization.
	RemoveMember(ctx context.Context, orgID, userID string) error
}

type assignmentService struct {
	deps     config.ModuleDependencies
	stores   Stores
	settings Settings
	access   AccessService
}

// NewAssignmentService creates the assignment service.
func NewAssignmentService(deps config.ModuleDependencies, stores Stores, settings Settings, accessService AccessService) *assignmentService {
	return &assignmentService{deps: deps, stores: stores, settings: settings, access: accessService}
}

func (s *assignmentService) Get(ctx context.Context, actor *Actor, userID string, scope access.Scope) (*UserRoles, *types.GoAuthError) {
	if actor != nil && actor.Principal.UserID == userID && userID != "" {
		if authErr := checkScope(s.settings, scope); authErr != nil {
			return nil, authErr
		}
	} else if _, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, scope, access.PermAssignmentsRead); authErr != nil {
		return nil, authErr
	}
	if _, authErr := s.target(ctx, userID, scope); authErr != nil {
		return nil, authErr
	}
	return s.userRoles(ctx, userID, scope)
}

func (s *assignmentService) Set(ctx context.Context, actor *Actor, userID string, scope access.Scope, keys []string) (*UserRoles, *types.GoAuthError) {
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, scope, access.PermAssignmentsWrite)
	if authErr != nil {
		return nil, authErr
	}
	membershipID, authErr := s.target(ctx, userID, scope)
	if authErr != nil {
		return nil, authErr
	}

	wanted := map[string]access.Set{}
	order := make([]string, 0, len(keys))
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if _, seen := wanted[key]; seen {
			continue
		}
		grants, authErr := s.assignable(ctx, scope, key)
		if authErr != nil {
			return nil, authErr
		}
		wanted[key] = grants
		order = append(order, key)
	}
	if len(order) > s.settings.MaxRolesPerUser {
		return nil, types.NewRBACLimitExceededError(fmt.Sprintf("A user may be assigned at most %d roles here", s.settings.MaxRolesPerUser))
	}

	current, authErr := s.current(ctx, userID, scope, membershipID)
	if authErr != nil {
		return nil, authErr
	}
	var add, remove []string
	for _, key := range order {
		if _, held := current[key]; !held {
			add = append(add, key)
		}
	}
	for key := range current {
		if _, keep := wanted[key]; !keep {
			remove = append(remove, key)
		}
	}
	sort.Strings(remove)

	for _, key := range add {
		if authErr := mustCover(holding, wanted[key]); authErr != nil {
			return nil, authErr
		}
	}
	for _, key := range remove {
		if authErr := mustCover(holding, s.grantsOf(ctx, scope, key)); authErr != nil {
			return nil, authErr
		}
	}
	for _, key := range add {
		if authErr := s.announce(ctx, actor, userID, scope, key); authErr != nil {
			return nil, authErr
		}
	}

	scopeType, scopeID := storageScope(scope)
	err := s.stores.RBAC.WithTransaction(ctx, func(tx types.RBACStorage) error {
		for _, key := range remove {
			if err := tx.Assignments().Delete(ctx, userID, scopeType, scopeID, key); err != nil {
				return err
			}
		}
		for _, key := range add {
			if err := s.create(ctx, tx, actor, userID, scope, key, membershipID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, types.NewInternalError("failed to update role assignments").Wrap(err)
	}
	ResetMemo(ctx)
	for _, key := range remove {
		s.emit(ctx, types.EventRBACRoleRevoked, actor, userID, scope, key)
	}
	for _, key := range add {
		s.emit(ctx, types.EventRBACRoleAssigned, actor, userID, scope, key)
	}
	return s.userRoles(ctx, userID, scope)
}

func (s *assignmentService) Assign(ctx context.Context, actor *Actor, userID string, scope access.Scope, key string) *types.GoAuthError {
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, scope, access.PermAssignmentsWrite)
	if authErr != nil {
		return authErr
	}
	membershipID, authErr := s.target(ctx, userID, scope)
	if authErr != nil {
		return authErr
	}
	grants, authErr := s.assignable(ctx, scope, key)
	if authErr != nil {
		return authErr
	}
	if authErr := mustCover(holding, grants); authErr != nil {
		return authErr
	}
	current, authErr := s.current(ctx, userID, scope, membershipID)
	if authErr != nil {
		return authErr
	}
	if _, held := current[key]; held {
		return nil
	}
	if len(current) >= s.settings.MaxRolesPerUser {
		return types.NewRBACLimitExceededError(fmt.Sprintf("A user may be assigned at most %d roles here", s.settings.MaxRolesPerUser))
	}
	if authErr := s.announce(ctx, actor, userID, scope, key); authErr != nil {
		return authErr
	}
	if err := s.create(ctx, s.stores.RBAC, actor, userID, scope, key, membershipID); err != nil {
		return types.NewInternalError("failed to assign role").Wrap(err)
	}
	ResetMemo(ctx)
	s.emit(ctx, types.EventRBACRoleAssigned, actor, userID, scope, key)
	return nil
}

func (s *assignmentService) Revoke(ctx context.Context, actor *Actor, userID string, scope access.Scope, key string) *types.GoAuthError {
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, scope, access.PermAssignmentsWrite)
	if authErr != nil {
		return authErr
	}
	if s.settings.IsImplied(scope.Type, key) {
		return impliedRoleError(key)
	}
	if authErr := mustCover(holding, s.grantsOf(ctx, scope, key)); authErr != nil {
		return authErr
	}
	scopeType, scopeID := storageScope(scope)
	existing, err := s.stores.RBAC.Assignments().ListByUser(ctx, userID, []models.RoleScopeRef{{Type: scopeType, ID: scopeID}})
	if err != nil {
		return types.NewInternalError("failed to load role assignments").Wrap(err)
	}
	held := false
	for _, assignment := range existing {
		if assignment.RoleKey == key {
			held = true
			break
		}
	}
	if !held {
		return nil
	}
	if err := s.stores.RBAC.Assignments().Delete(ctx, userID, scopeType, scopeID, key); err != nil {
		return types.NewInternalError("failed to revoke role").Wrap(err)
	}
	ResetMemo(ctx)
	s.emit(ctx, types.EventRBACRoleRevoked, actor, userID, scope, key)
	return nil
}

func (s *assignmentService) List(ctx context.Context, actor *Actor, scope access.Scope, opts models.RoleAssignmentListOpts) ([]*models.RoleAssignment, int64, *types.GoAuthError) {
	if _, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, scope, access.PermAssignmentsRead); authErr != nil {
		return nil, 0, authErr
	}
	scopeType, scopeID := storageScope(scope)
	assignments, total, err := s.stores.RBAC.Assignments().ListByScope(ctx, scopeType, scopeID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list role assignments").Wrap(err)
	}
	return assignments, total, nil
}

func (s *assignmentService) RemoveUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return s.stores.RBAC.Assignments().DeleteByUser(ctx, userID)
}

func (s *assignmentService) RemoveMember(ctx context.Context, orgID, userID string) error {
	if orgID == "" || userID == "" {
		return nil
	}
	return s.stores.RBAC.Assignments().DeleteByUserAndScope(ctx, userID, models.RoleScopeOrg, orgID)
}

// target checks that userID can hold roles in scope and returns the
// membership the assignment is tied to: empty for the global scope, the
// organization membership row otherwise.
func (s *assignmentService) target(ctx context.Context, userID string, scope access.Scope) (string, *types.GoAuthError) {
	if userID == "" {
		return "", types.NewUserNotFoundError()
	}
	if !scope.IsOrg() {
		user, err := s.stores.Users.FindByID(ctx, userID)
		if errors.Is(err, models.ErrNotFound) || (err == nil && (user == nil || user.ID != userID)) {
			return "", types.NewUserNotFoundError()
		}
		if err != nil {
			return "", types.NewInternalError("failed to load user").Wrap(err)
		}
		return "", nil
	}
	member, err := s.stores.Members.FindByOrgAndUser(ctx, scope.ID, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (member == nil || member.OrgID != scope.ID || member.UserID != userID)) {
		return "", types.NewOrgMemberNotFoundError()
	}
	if err != nil {
		return "", types.NewInternalError("failed to load organization membership").Wrap(err)
	}
	return member.ID, nil
}

// assignable returns the grants of a role that may be assigned in scope.
func (s *assignmentService) assignable(ctx context.Context, scope access.Scope, key string) (access.Set, *types.GoAuthError) {
	if s.settings.IsImplied(scope.Type, key) {
		return nil, impliedRoleError(key)
	}
	if role, defined := s.settings.Role(scope.Type, key); defined {
		return access.ParseSetLenient(role.Grants), nil
	}
	role, authErr := findStoredRole(ctx, s.stores, scope, key)
	if authErr != nil {
		return nil, authErr
	}
	return access.ParseSetLenient(role.Grants), nil
}

// grantsOf returns what a role allows, or nothing when the role no longer
// exists. It is used when a role is taken away, where a missing role must
// not block the removal.
func (s *assignmentService) grantsOf(ctx context.Context, scope access.Scope, key string) access.Set {
	if role, defined := s.settings.Role(scope.Type, key); defined {
		return access.ParseSetLenient(role.Grants)
	}
	role, authErr := findStoredRole(ctx, s.stores, scope, key)
	if authErr != nil {
		return nil
	}
	return access.ParseSetLenient(role.Grants)
}

// current returns the roles assigned to the user in scope that still count.
// Rows left behind by an earlier membership are deleted on the way.
func (s *assignmentService) current(ctx context.Context, userID string, scope access.Scope, membershipID string) (map[string]struct{}, *types.GoAuthError) {
	scopeType, scopeID := storageScope(scope)
	assignments, err := s.stores.RBAC.Assignments().ListByUser(ctx, userID, []models.RoleScopeRef{{Type: scopeType, ID: scopeID}})
	if err != nil {
		return nil, types.NewInternalError("failed to load role assignments").Wrap(err)
	}
	current := map[string]struct{}{}
	for _, assignment := range assignments {
		stale := assignment.MembershipID != membershipID || s.settings.IsImplied(scope.Type, assignment.RoleKey)
		if stale {
			if err := s.stores.RBAC.Assignments().Delete(ctx, userID, scopeType, scopeID, assignment.RoleKey); err != nil {
				return nil, types.NewInternalError("failed to remove stale role assignment").Wrap(err)
			}
			continue
		}
		current[assignment.RoleKey] = struct{}{}
	}
	return current, nil
}

func (s *assignmentService) create(ctx context.Context, store types.RBACStorage, actor *Actor, userID string, scope access.Scope, key, membershipID string) error {
	scopeType, scopeID := storageScope(scope)
	err := store.Assignments().Create(ctx, &models.RoleAssignment{
		UserID:       userID,
		ScopeType:    scopeType,
		ScopeID:      scopeID,
		RoleKey:      key,
		MembershipID: membershipID,
		GrantedBy:    actor.userID(),
	})
	if errors.Is(err, models.ErrConflict) {
		return nil
	}
	return err
}

// announce gives subscribers of the before-assign event the chance to refuse
// the change.
func (s *assignmentService) announce(ctx context.Context, actor *Actor, userID string, scope access.Scope, key string) *types.GoAuthError {
	scopeType, scopeID := storageScope(scope)
	err := s.deps.Events.EmitSync(ctx, types.EventBeforeRBACRoleAssign, &types.RBACAssignmentEventData{
		UserID: userID, RoleKey: key, ScopeType: scopeType, ScopeID: scopeID, ActorID: actor.userID(),
	})
	if err == nil {
		return nil
	}
	var authErr *types.GoAuthError
	if errors.As(err, &authErr) {
		if authErr.StatusCode < http.StatusBadRequest || authErr.StatusCode > 599 {
			refused := *authErr
			refused.StatusCode = http.StatusForbidden
			return &refused
		}
		return authErr
	}
	reason := err
	if inner := errors.Unwrap(err); inner != nil {
		reason = inner
	}
	return types.NewRBACAssignmentRefusedError(reason.Error())
}

func (s *assignmentService) emit(ctx context.Context, event types.EventType, actor *Actor, userID string, scope access.Scope, key string) {
	scopeType, scopeID := storageScope(scope)
	_ = s.deps.Events.EmitAsync(ctx, event, &types.RBACAssignmentEventData{
		UserID: userID, RoleKey: key, ScopeType: scopeType, ScopeID: scopeID, ActorID: actor.userID(),
	})
}

func (s *assignmentService) userRoles(ctx context.Context, userID string, scope access.Scope) (*UserRoles, *types.GoAuthError) {
	holding, authErr := s.access.Holding(ctx, userID, scope)
	if authErr != nil {
		return nil, authErr
	}
	return &UserRoles{UserID: userID, Scope: scope, Roles: holding.Roles, Grants: holding.Grants.Strings()}, nil
}

func impliedRoleError(key string) *types.GoAuthError {
	if key == access.RoleSuperAdmin {
		return types.NewRBACRoleSystemError("The super admin role comes from the user's super admin flag and cannot be assigned")
	}
	return types.NewRBACRoleSystemError("This role comes from organization membership and cannot be assigned; change the member's role instead")
}
