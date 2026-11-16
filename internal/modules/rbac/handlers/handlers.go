// Package handlers serves the rbac endpoints: the permission catalog, the
// caller's own permissions, roles and role assignments.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

const maxListLimit = 100

// Path parameters of the rbac routes.
const (
	ParamOrgID   = "orgId"
	ParamTeamID  = "teamId"
	ParamRoleKey = "roleKey"
	ParamUserID  = "userId"
)

// Handler serves the rbac endpoints. The same handlers serve the
// application-wide routes and the organization routes; which one a request
// is for is read from its path.
type Handler struct {
	deps          config.ModuleDependencies
	access        services.AccessService
	roles         services.RoleService
	assignments   services.AssignmentService
	catalog       func() []dto.PermissionDTO
	organizations bool
}

// NewHandler creates the rbac handler. catalog returns the permissions the
// application has declared so far.
func NewHandler(deps config.ModuleDependencies, access services.AccessService, roles services.RoleService, assignments services.AssignmentService, catalog func() []dto.PermissionDTO, organizations bool) *Handler {
	return &Handler{deps: deps, access: access, roles: roles, assignments: assignments, catalog: catalog, organizations: organizations}
}

// ListPermissions returns the permission catalog.
func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	verdict, authErr := h.access.Authorize(r.Context(), services.AuthorizeRequest{
		Principal:  actor.Principal,
		UserID:     actor.Principal.UserID,
		Permission: access.PermRolesRead,
		Scope:      h.ownScope(r, actor),
		Request:    r,
	})
	if authErr != nil {
		respond(w, authErr)
		return
	}
	if !verdict.Allowed {
		respond(w, services.DeniedError(verdict.Check))
		return
	}
	http_utils.RespondSuccess(w, h.catalog(), nil)
}

// MyPermissions returns what the caller holds, for a client that wants to
// hide what the caller cannot do. It answers for any organization: someone
// who is not a member there holds their application-wide roles and nothing
// else, which is also what a check would find.
func (h *Handler) MyPermissions(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	scope := h.ownScope(r, actor)
	holding, authErr := h.access.Holding(r.Context(), actor.Principal.UserID, scope)
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, dto.UserRolesToDTO(&services.UserRoles{
		UserID: actor.Principal.UserID,
		Scope:  scope,
		Roles:  holding.Roles,
		Grants: holding.Grants.Strings(),
	}), nil)
}

// ListRoles lists the roles of a scope, built-in and custom.
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	opts := models.RoleListOpts{ListingOpts: http_utils.ParseListingOpts(r), Query: r.URL.Query().Get("query")}
	opts.Normalize(maxListLimit)

	roles, total, authErr := h.roles.List(r.Context(), actor, routeScope(r), opts)
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondList(w, dto.RolesToDTO(roles), total, opts.SortField, opts.SortDir)
}

// GetRole returns one role.
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	role, authErr := h.roles.Get(r.Context(), actor, routeScope(r), r.PathValue(ParamRoleKey))
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, dto.RoleToDTO(role), nil)
}

// CreateRole creates a custom role.
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req dto.CreateRoleRequest
	if !decode(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	role, authErr := h.roles.Create(r.Context(), actor, routeScope(r), services.RoleInput{
		Key: req.Key, Name: req.Name, Description: req.Description, Grants: req.Grants,
	})
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondCreated(w, dto.RoleToDTO(role), nil)
}

// UpdateRole changes a custom role.
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req dto.UpdateRoleRequest
	if !decode(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	role, authErr := h.roles.Update(r.Context(), actor, routeScope(r), r.PathValue(ParamRoleKey), services.RolePatch{
		Name: req.Name, Description: req.Description, Grants: req.Grants,
	})
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, dto.RoleToDTO(role), nil)
}

// DeleteRole deletes a custom role and takes it away from everyone.
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	if authErr := h.roles.Delete(r.Context(), actor, routeScope(r), r.PathValue(ParamRoleKey)); authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess[any](w, nil, nil)
}

// GetUserRoles returns what a user holds in a scope.
func (h *Handler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	roles, authErr := h.assignments.Get(r.Context(), actor, r.PathValue(ParamUserID), routeScope(r))
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, dto.UserRolesToDTO(roles), nil)
}

// SetUserRoles replaces the roles assigned to a user in a scope.
func (h *Handler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	var req dto.SetRolesRequest
	if !decode(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	roles, authErr := h.assignments.Set(r.Context(), actor, r.PathValue(ParamUserID), routeScope(r), *req.Roles)
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, dto.UserRolesToDTO(roles), nil)
}

// ListAssignments lists the role assignments made in a scope.
func (h *Handler) ListAssignments(w http.ResponseWriter, r *http.Request) {
	r, actor, ok := h.begin(w, r)
	if !ok {
		return
	}
	opts := models.RoleAssignmentListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		UserID:      r.URL.Query().Get("user_id"),
		RoleKey:     r.URL.Query().Get("role"),
	}
	opts.Normalize(maxListLimit)

	assignments, total, authErr := h.assignments.List(r.Context(), actor, routeScope(r), opts)
	if authErr != nil {
		respond(w, authErr)
		return
	}
	http_utils.RespondList(w, dto.AssignmentsToDTO(assignments), total, opts.SortField, opts.SortDir)
}

// begin reads the caller and gives the request a memo, so that the checks
// made while serving it load the caller's roles once.
func (h *Handler) begin(w http.ResponseWriter, r *http.Request) (*http.Request, *services.Actor, bool) {
	principal, ok := types.PrincipalFromContext(r.Context())
	if !ok || principal.UserID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Authentication required")
		return r, nil, false
	}
	return r.WithContext(services.WithMemo(r.Context())), &services.Actor{Principal: principal}, true
}

// ownScope is the scope the caller asks about themselves: the organization
// in the org_id query parameter, else the one they are signed in to, else
// the whole application.
func (h *Handler) ownScope(r *http.Request, actor *services.Actor) access.Scope {
	if orgID := r.URL.Query().Get("org_id"); orgID != "" {
		return access.OrgScope(orgID)
	}
	if h.organizations && actor.Principal.OrganizationID != "" {
		return access.OrgScope(actor.Principal.OrganizationID)
	}
	return access.GlobalScope()
}

// routeScope is the scope a role or assignment route is about: the
// organization in its path, or the whole application.
func routeScope(r *http.Request) access.Scope {
	orgID := r.PathValue(ParamOrgID)
	if teamID := r.PathValue(ParamTeamID); teamID != "" {
		// The organization in the path must be the team's own; the services
		// treat a team of another organization as not found.
		scope := access.TeamScope(teamID)
		scope.Org = orgID
		return scope
	}
	if orgID != "" {
		return access.OrgScope(orgID)
	}
	return access.GlobalScope()
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return false
	}
	return true
}

func respond(w http.ResponseWriter, authErr *types.GoAuthError) {
	status := authErr.StatusCode
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusInternalServerError
	}
	http_utils.RespondError(w, status, string(authErr.Code), authErr.Message)
}
