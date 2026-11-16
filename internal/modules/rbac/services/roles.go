package services

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

const (
	maxRoleNameLength        = 255
	maxRoleDescriptionLength = 1000
)

var roleKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidRoleKey reports whether key is acceptable as a role key: lowercase
// letters, digits, "_" and "-", at most 64 characters.
func ValidRoleKey(key string) bool {
	return roleKeyPattern.MatchString(key)
}

// Actor is the signed-in user making a change through the API. A nil *Actor
// means the change comes from the application's own code: it is trusted, and
// neither permissions nor the "no more than you hold" rule are applied.
type Actor struct {
	Principal types.Principal
}

func (a *Actor) userID() string {
	if a == nil {
		return ""
	}
	return a.Principal.UserID
}

// RoleView is a role as the API shows it, whether it is defined in code or
// stored.
type RoleView struct {
	Key         string
	Name        string
	Description string
	Grants      []string
	// Scope is where the role is held: "global" or "org".
	Scope access.ScopeType
	OrgID string
	// System roles are defined in code and cannot be changed through the API.
	System bool
	// Implied roles come from the super admin flag or from organization
	// membership and cannot be assigned.
	Implied   bool
	CreatedBy string
	CreatedAt *time.Time
	UpdatedAt *time.Time
}

// RoleInput is the data for a new role.
type RoleInput struct {
	Key         string
	Name        string
	Description string
	Grants      []string
}

// RolePatch changes a role. Nil fields are left as they are.
type RolePatch struct {
	Name        *string
	Description *string
	Grants      *[]string
}

// RoleService manages the roles of one scope: the ones defined in code,
// which are read-only, and the ones created at runtime.
type RoleService interface {
	List(ctx context.Context, actor *Actor, scope access.Scope, opts models.RoleListOpts) ([]*RoleView, int64, *types.GoAuthError)
	Get(ctx context.Context, actor *Actor, scope access.Scope, key string) (*RoleView, *types.GoAuthError)
	Create(ctx context.Context, actor *Actor, scope access.Scope, input RoleInput) (*RoleView, *types.GoAuthError)
	Update(ctx context.Context, actor *Actor, scope access.Scope, key string, patch RolePatch) (*RoleView, *types.GoAuthError)
	Delete(ctx context.Context, actor *Actor, scope access.Scope, key string) *types.GoAuthError
	// RemoveOrganization deletes the roles and assignments of an
	// organization that no longer exists.
	RemoveOrganization(ctx context.Context, orgID string) error
}

type roleService struct {
	deps     config.ModuleDependencies
	stores   Stores
	settings Settings
	access   AccessService
}

// NewRoleService creates the role service.
func NewRoleService(deps config.ModuleDependencies, stores Stores, settings Settings, accessService AccessService) *roleService {
	return &roleService{deps: deps, stores: stores, settings: settings, access: accessService}
}

func (s *roleService) List(ctx context.Context, actor *Actor, scope access.Scope, opts models.RoleListOpts) ([]*RoleView, int64, *types.GoAuthError) {
	if _, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, &scope, access.PermRolesRead); authErr != nil {
		return nil, 0, authErr
	}
	views := systemRoleViews(s.settings, scope)
	stored, err := s.stores.RBAC.Roles().ListByOrg(ctx, scope.OrgID())
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list roles").Wrap(err)
	}
	for _, role := range stored {
		if role.OrgID != scope.OrgID() {
			continue
		}
		views = append(views, storedRoleView(role, scope))
	}

	if query := strings.ToLower(opts.Query); query != "" {
		filtered := views[:0]
		for _, view := range views {
			if strings.Contains(view.Key, query) || strings.Contains(strings.ToLower(view.Name), query) {
				filtered = append(filtered, view)
			}
		}
		views = filtered
	}
	sortRoleViews(views, opts.SortField, opts.SortDir)

	total := int64(len(views))
	if opts.Offset >= len(views) {
		return []*RoleView{}, total, nil
	}
	end := min(opts.Offset+opts.Limit, len(views))
	return views[opts.Offset:end], total, nil
}

func (s *roleService) Get(ctx context.Context, actor *Actor, scope access.Scope, key string) (*RoleView, *types.GoAuthError) {
	if _, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, &scope, access.PermRolesRead); authErr != nil {
		return nil, authErr
	}
	return findRoleView(ctx, s.stores, s.settings, scope, key)
}

func (s *roleService) Create(ctx context.Context, actor *Actor, scope access.Scope, input RoleInput) (*RoleView, *types.GoAuthError) {
	if scope.IsTeam() {
		return nil, types.NewRBACScopeUnavailableError("Roles are created per organization; assign the organization's roles in its teams")
	}
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, &scope, access.PermRolesWrite)
	if authErr != nil {
		return nil, authErr
	}

	key := strings.TrimSpace(input.Key)
	if !ValidRoleKey(key) {
		return nil, types.NewRBACInvalidRoleError("Role key must be 1 to 64 lowercase letters, digits, '_' or '-'")
	}
	if key == access.RoleSuperAdmin || s.settings.IsImplied(scope.Type, key) {
		return nil, types.NewRBACRoleSystemError("This role key is reserved")
	}
	if _, defined := s.settings.Role(scope.Type, key); defined {
		return nil, types.NewRBACRoleExistsError()
	}
	name, description, authErr := cleanRoleText(input.Name, input.Description)
	if authErr != nil {
		return nil, authErr
	}
	grants, authErr := s.cleanGrants(input.Grants)
	if authErr != nil {
		return nil, authErr
	}
	if authErr := mustCover(holding, grants); authErr != nil {
		return nil, authErr
	}

	count, err := s.stores.RBAC.Roles().CountByOrg(ctx, scope.OrgID())
	if err != nil {
		return nil, types.NewInternalError("failed to count roles").Wrap(err)
	}
	if count >= int64(s.settings.MaxRolesPerScope) {
		return nil, types.NewRBACLimitExceededError(fmt.Sprintf("No more than %d custom roles are allowed here", s.settings.MaxRolesPerScope))
	}

	role := &models.Role{
		OrgID:       scope.OrgID(),
		Key:         key,
		Name:        name,
		Description: description,
		Grants:      grants.Strings(),
		CreatedBy:   actor.userID(),
	}
	if err := s.stores.RBAC.Roles().Create(ctx, role); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewRBACRoleExistsError()
		}
		return nil, types.NewInternalError("failed to create role").Wrap(err)
	}
	ResetMemo(ctx)
	_ = s.deps.Events.EmitAsync(ctx, types.EventRBACRoleCreated, &types.RBACRoleEventData{Role: role, ActorID: actor.userID()})
	return storedRoleView(role, scope), nil
}

func (s *roleService) Update(ctx context.Context, actor *Actor, scope access.Scope, key string, patch RolePatch) (*RoleView, *types.GoAuthError) {
	if scope.IsTeam() {
		return nil, types.NewRBACScopeUnavailableError("Roles are created per organization; assign the organization's roles in its teams")
	}
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, &scope, access.PermRolesWrite)
	if authErr != nil {
		return nil, authErr
	}
	role, authErr := s.storedRole(ctx, scope, key)
	if authErr != nil {
		return nil, authErr
	}
	// The role is being taken out of other people's hands as much as it is
	// being given new powers, so both the old and the new grants must be
	// within what the caller holds.
	if authErr := mustCover(holding, access.ParseSetLenient(role.Grants)); authErr != nil {
		return nil, authErr
	}

	name, description := role.Name, role.Description
	if patch.Name != nil {
		name = *patch.Name
	}
	if patch.Description != nil {
		description = *patch.Description
	}
	name, description, authErr = cleanRoleText(name, description)
	if authErr != nil {
		return nil, authErr
	}
	role.Name, role.Description = name, description
	if patch.Grants != nil {
		grants, authErr := s.cleanGrants(*patch.Grants)
		if authErr != nil {
			return nil, authErr
		}
		if authErr := mustCover(holding, grants); authErr != nil {
			return nil, authErr
		}
		role.Grants = grants.Strings()
	}

	if err := s.stores.RBAC.Roles().Update(ctx, role); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewRBACRoleNotFoundError()
		}
		return nil, types.NewInternalError("failed to update role").Wrap(err)
	}
	ResetMemo(ctx)
	_ = s.deps.Events.EmitAsync(ctx, types.EventRBACRoleUpdated, &types.RBACRoleEventData{Role: role, ActorID: actor.userID()})
	return storedRoleView(role, scope), nil
}

func (s *roleService) Delete(ctx context.Context, actor *Actor, scope access.Scope, key string) *types.GoAuthError {
	if scope.IsTeam() {
		return types.NewRBACScopeUnavailableError("Roles are created per organization; assign the organization's roles in its teams")
	}
	holding, authErr := authorizeActor(ctx, s.access, s.settings, s.stores, actor, &scope, access.PermRolesWrite)
	if authErr != nil {
		return authErr
	}
	role, authErr := s.storedRole(ctx, scope, key)
	if authErr != nil {
		return authErr
	}
	if authErr := mustCover(holding, access.ParseSetLenient(role.Grants)); authErr != nil {
		return authErr
	}

	// The assignments go in the same transaction: a role created later with
	// the same key must not inherit the people who held this one.
	scopeType, scopeID := storageScope(scope)
	err := s.stores.RBAC.WithTransaction(ctx, func(tx types.RBACStorage) error {
		if err := tx.Assignments().DeleteByRole(ctx, scopeType, scopeID, role.Key); err != nil {
			return err
		}
		return tx.Roles().Delete(ctx, role.ID)
	})
	if err != nil {
		return types.NewInternalError("failed to delete role").Wrap(err)
	}
	ResetMemo(ctx)
	_ = s.deps.Events.EmitAsync(ctx, types.EventRBACRoleDeleted, &types.RBACRoleEventData{Role: role, ActorID: actor.userID()})
	return nil
}

func (s *roleService) RemoveOrganization(ctx context.Context, orgID string) error {
	if orgID == "" {
		return nil
	}
	return s.stores.RBAC.WithTransaction(ctx, func(tx types.RBACStorage) error {
		if err := tx.Assignments().DeleteByScope(ctx, models.RoleScopeOrg, orgID); err != nil {
			return err
		}
		return tx.Roles().DeleteByOrg(ctx, orgID)
	})
}

// storedRole returns a role created at runtime. Roles defined in code are
// refused: they are changed in code.
func (s *roleService) storedRole(ctx context.Context, scope access.Scope, key string) (*models.Role, *types.GoAuthError) {
	if key == access.RoleSuperAdmin || s.settings.IsImplied(scope.Type, key) {
		return nil, types.NewRBACRoleSystemError("This role is built in and cannot be changed")
	}
	if _, defined := s.settings.Role(scope.Type, key); defined {
		return nil, types.NewRBACRoleSystemError("This role is defined in code and cannot be changed through the API")
	}
	return findStoredRole(ctx, s.stores, scope, key)
}

// cleanGrants parses, de-duplicates and bounds the grants of a role.
func (s *roleService) cleanGrants(raw []string) (access.Set, *types.GoAuthError) {
	trimmed := make([]string, 0, len(raw))
	for _, grant := range raw {
		trimmed = append(trimmed, strings.TrimSpace(grant))
	}
	parsed, err := access.ParseSet(trimmed)
	if err != nil {
		return nil, types.NewRBACInvalidRoleError("Invalid grant: " + err.Error())
	}
	unique, err := access.ParseSet(parsed.Strings())
	if err != nil {
		return nil, types.NewRBACInvalidRoleError("Invalid grant: " + err.Error())
	}
	if len(unique) > s.settings.MaxGrantsPerRole {
		return nil, types.NewRBACLimitExceededError(fmt.Sprintf("A role may have at most %d grants", s.settings.MaxGrantsPerRole))
	}
	return unique, nil
}

func cleanRoleText(name, description string) (string, string, *types.GoAuthError) {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if name == "" {
		return "", "", types.NewRBACInvalidRoleError("Role name is required")
	}
	if len(name) > maxRoleNameLength {
		return "", "", types.NewRBACInvalidRoleError(fmt.Sprintf("Role name may be at most %d characters", maxRoleNameLength))
	}
	if len(description) > maxRoleDescriptionLength {
		return "", "", types.NewRBACInvalidRoleError(fmt.Sprintf("Role description may be at most %d characters", maxRoleDescriptionLength))
	}
	return name, description, nil
}

// mustCover enforces that a caller cannot manage a role that allows more
// than the caller holds. A nil holding is trusted code.
func mustCover(holding *Holding, grants access.Set) *types.GoAuthError {
	if holding == nil {
		return nil
	}
	if missing, ok := holding.Grants.CoversAll(grants); !ok {
		return types.NewRBACGrantNotHeldError(missing.String())
	}
	return nil
}

// authorizeActor checks that the scope can be managed and that the actor
// holds permission in it. It returns the actor's holding, or nil for trusted
// code.
func authorizeActor(ctx context.Context, accessService AccessService, settings Settings, stores Stores, actor *Actor, scopeRef *access.Scope, permission string) (*Holding, *types.GoAuthError) {
	if authErr := checkScope(settings, *scopeRef); authErr != nil {
		return nil, authErr
	}
	if scopeRef.IsTeam() {
		// The team's organization becomes part of the scope, for the roles
		// and memberships read from here on.
		team, err := stores.Teams.FindByID(ctx, scopeRef.ID)
		if errors.Is(err, models.ErrNotFound) || (err == nil && (team == nil || team.ID != scopeRef.ID || (scopeRef.Org != "" && scopeRef.Org != team.OrgID))) {
			return nil, types.NewTeamNotFoundError()
		}
		if err != nil {
			return nil, types.NewInternalError("failed to load team").Wrap(err)
		}
		scopeRef.Org = team.OrgID
	}
	scope := *scopeRef
	if orgID := scope.OrgID(); orgID != "" {
		org, err := stores.Orgs.FindByID(ctx, orgID)
		if errors.Is(err, models.ErrNotFound) || (err == nil && (org == nil || org.ID != orgID)) {
			return nil, types.NewOrgNotFoundError()
		}
		if err != nil {
			return nil, types.NewInternalError("failed to load organization").Wrap(err)
		}
		if !org.Active {
			return nil, types.NewOrgNotFoundError()
		}
	}
	if actor == nil {
		return nil, nil
	}
	if actor.Principal.UserID == "" {
		return nil, types.NewUnauthorizedError()
	}
	verdict, authErr := accessService.Authorize(ctx, AuthorizeRequest{
		Principal:  actor.Principal,
		UserID:     actor.Principal.UserID,
		Permission: permission,
		Scope:      scope,
	})
	if authErr != nil {
		return nil, authErr
	}
	if !verdict.Allowed {
		return nil, DeniedError(verdict.Check)
	}
	return verdict.Holding, nil
}

// DeniedError is the error returned for a refused check.
func DeniedError(check access.Check) *types.GoAuthError {
	if check.Reason != "" {
		return types.NewRBACPermissionDeniedError(check.Reason)
	}
	return types.NewRBACPermissionDeniedError("Missing permission: " + check.Permission)
}

// findRoleView returns the role with key in scope, defined in code or stored.
func findRoleView(ctx context.Context, stores Stores, settings Settings, scope access.Scope, key string) (*RoleView, *types.GoAuthError) {
	if role, defined := settings.Role(scope.Type, key); defined {
		return systemRoleView(settings, role, scope), nil
	}
	role, authErr := findStoredRole(ctx, stores, scope, key)
	if authErr != nil {
		return nil, authErr
	}
	return storedRoleView(role, scope), nil
}

func findStoredRole(ctx context.Context, stores Stores, scope access.Scope, key string) (*models.Role, *types.GoAuthError) {
	if !ValidRoleKey(key) {
		return nil, types.NewRBACRoleNotFoundError()
	}
	role, err := stores.RBAC.Roles().FindByKey(ctx, scope.OrgID(), key)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (role == nil || role.Key != key || role.OrgID != scope.OrgID())) {
		return nil, types.NewRBACRoleNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load role").Wrap(err)
	}
	return role, nil
}

func systemRoleViews(settings Settings, scope access.Scope) []*RoleView {
	views := make([]*RoleView, 0, len(settings.Roles[scope.Type]))
	for _, role := range settings.Roles[scope.Type] {
		views = append(views, systemRoleView(settings, role, scope))
	}
	return views
}

func systemRoleView(settings Settings, role access.Role, scope access.Scope) *RoleView {
	return &RoleView{
		Key:         role.Key,
		Name:        role.Name,
		Description: role.Description,
		Grants:      access.ParseSetLenient(role.Grants).Strings(),
		Scope:       scope.Type,
		OrgID:       scope.OrgID(),
		System:      true,
		Implied:     settings.IsImplied(scope.Type, role.Key),
	}
}

func storedRoleView(role *models.Role, scope access.Scope) *RoleView {
	createdAt := role.CreatedAt
	return &RoleView{
		Key:         role.Key,
		Name:        role.Name,
		Description: role.Description,
		Grants:      access.ParseSetLenient(role.Grants).Strings(),
		Scope:       scope.Type,
		OrgID:       role.OrgID,
		CreatedBy:   role.CreatedBy,
		CreatedAt:   &createdAt,
		UpdatedAt:   role.UpdatedAt,
	}
}

// sortRoleViews orders roles for listing. Roles defined in code have no
// creation time and sort before stored ones; the key breaks every tie so the
// order is stable across pages.
func sortRoleViews(views []*RoleView, field, dir string) {
	less := func(a, b *RoleView) bool {
		switch field {
		case "key":
			return a.Key < b.Key
		case "name":
			if a.Name != b.Name {
				return strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
			return a.Key < b.Key
		default:
			switch {
			case a.CreatedAt == nil && b.CreatedAt == nil:
				return a.Key < b.Key
			case a.CreatedAt == nil:
				return true
			case b.CreatedAt == nil:
				return false
			case !a.CreatedAt.Equal(*b.CreatedAt):
				return a.CreatedAt.Before(*b.CreatedAt)
			default:
				return a.Key < b.Key
			}
		}
	}
	sort.SliceStable(views, func(i, j int) bool {
		if dir == "desc" {
			return less(views[j], views[i])
		}
		return less(views[i], views[j])
	})
}
