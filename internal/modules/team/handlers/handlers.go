// Package handlers serves the team module's JSON API.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/team/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Handler serves the team routes.
type Handler struct {
	service services.TeamService
	users   models.UserRepository
}

// New creates the handler.
func New(service services.TeamService, users models.UserRepository) *Handler {
	return &Handler{service: service, users: users}
}

// Routes returns the team module's routes, all under /org/{orgId}/teams and
// all for signed-in users; the service decides who may do what.
func (h *Handler) Routes() []config.RouteInfo {
	auth := []types.MiddlewareName{types.MiddlewareAuth}
	route := func(name types.RouteName, method, path string, handler http.HandlerFunc) config.RouteInfo {
		return config.RouteInfo{Name: string(name), Method: method, Path: "/org/{orgId}/teams" + path, Handler: handler, Middlewares: auth}
	}
	return []config.RouteInfo{
		route(types.RouteTeamList, http.MethodGet, "", h.List),
		route(types.RouteTeamCreate, http.MethodPost, "", h.Create),
		route(types.RouteTeamGet, http.MethodGet, "/{teamId}", h.Get),
		route(types.RouteTeamUpdate, http.MethodPut, "/{teamId}", h.Update),
		route(types.RouteTeamMove, http.MethodPost, "/{teamId}/move", h.Move),
		route(types.RouteTeamDelete, http.MethodDelete, "/{teamId}", h.Delete),
		route(types.RouteTeamMembersList, http.MethodGet, "/{teamId}/members", h.ListMembers),
		route(types.RouteTeamMembersAdd, http.MethodPost, "/{teamId}/members", h.AddMember),
		route(types.RouteTeamMembersUpdate, http.MethodPut, "/{teamId}/members/{userId}", h.UpdateMember),
		route(types.RouteTeamMembersRemove, http.MethodDelete, "/{teamId}/members/{userId}", h.RemoveMember),
	}
}

// TeamDTO is a team as the API returns it.
type TeamDTO struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	ParentID    string     `json:"parent_id,omitempty"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Description string     `json:"description,omitempty"`
	Depth       int        `json:"depth"`
	Ancestors   []string   `json:"ancestors"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func teamDTO(team *models.Team) TeamDTO {
	ancestors := team.AncestorIDs()
	return TeamDTO{ID: team.ID, OrgID: team.OrgID, ParentID: team.ParentID, Name: team.Name, Slug: team.Slug, Description: team.Description,
		Depth: team.Depth, Ancestors: ancestors[:len(ancestors)-1], CreatedAt: team.CreatedAt, UpdatedAt: team.UpdatedAt}
}

func teamDTOs(teams []*models.Team) []TeamDTO {
	out := make([]TeamDTO, 0, len(teams))
	for _, team := range teams {
		out = append(out, teamDTO(team))
	}
	return out
}

// MemberDTO is a team membership as the API returns it.
type MemberDTO struct {
	TeamID    string    `json:"team_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func memberDTO(member *models.TeamMember) MemberDTO {
	return MemberDTO{TeamID: member.TeamID, UserID: member.UserID, Role: member.Role, CreatedAt: member.CreatedAt}
}

// TeamRequest creates or edits a team.
type TeamRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
}

// MoveRequest moves a team; an empty parent_id moves it to the top.
type MoveRequest struct {
	ParentID string `json:"parent_id"`
}

// MemberRequest adds a member or changes a member's role.
type MemberRequest struct {
	UserID string `json:"user_id,omitempty"`
	Role   string `json:"role,omitempty"`
}

func (h *Handler) actor(r *http.Request) *services.Actor {
	userID, _ := r.Context().Value(types.UserIDKey).(string)
	actor := &services.Actor{UserID: userID}
	if user, err := h.users.FindByID(r.Context(), userID); err == nil && user != nil && user.IsSuperAdmin && user.Active {
		actor.SuperAdmin = true
	}
	return actor
}

func fail(w http.ResponseWriter, authErr *types.GoAuthError) {
	http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(into); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "invalid request body")
		return false
	}
	return true
}

// List returns the organization's teams. ?tree=true returns every team in
// tree order instead of a page; ?parent_id= lists one team's children and
// ?top=true the top-level teams.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("orgId")
	if r.URL.Query().Get("tree") == "true" {
		teams, authErr := h.service.Tree(r.Context(), h.actor(r), orgID)
		if authErr != nil {
			fail(w, authErr)
			return
		}
		http_utils.RespondList(w, teamDTOs(teams), int64(len(teams)), "path", "asc")
		return
	}
	opts := models.TeamListOpts{ListingOpts: http_utils.ParseListingOpts(r), ParentID: r.URL.Query().Get("parent_id"), Top: r.URL.Query().Get("top") == "true", Query: r.URL.Query().Get("q")}
	opts.Normalize(100)
	teams, total, authErr := h.service.List(r.Context(), h.actor(r), orgID, opts)
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondList(w, teamDTOs(teams), total, opts.SortField, opts.SortDir)
}

// Create makes a team.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req TeamRequest
	if !decode(w, r, &req) {
		return
	}
	team, authErr := h.service.Create(r.Context(), h.actor(r), r.PathValue("orgId"), services.TeamInput{Name: req.Name, Slug: req.Slug, Description: req.Description, ParentID: req.ParentID})
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondCreated(w, teamDTO(team), nil)
}

// Get returns one team.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	team, authErr := h.service.Get(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"))
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, teamDTO(team), nil)
}

// Update renames a team or changes its slug or description.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var req TeamRequest
	if !decode(w, r, &req) {
		return
	}
	team, authErr := h.service.Update(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), services.TeamInput{Name: req.Name, Slug: req.Slug, Description: req.Description})
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, teamDTO(team), nil)
}

// Move puts a team beneath another, or at the top.
func (h *Handler) Move(w http.ResponseWriter, r *http.Request) {
	var req MoveRequest
	if !decode(w, r, &req) {
		return
	}
	team, authErr := h.service.Move(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), strings.TrimSpace(req.ParentID))
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, teamDTO(team), nil)
}

// Delete removes a team that has no teams beneath it.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if authErr := h.service.Delete(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId")); authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, map[string]string{"message": "team deleted"}, nil)
}

// ListMembers returns a team's members.
func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	opts := models.TeamMemberListOpts{ListingOpts: http_utils.ParseListingOpts(r), Role: r.URL.Query().Get("role")}
	opts.Normalize(100)
	members, total, authErr := h.service.ListMembers(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), opts)
	if authErr != nil {
		fail(w, authErr)
		return
	}
	out := make([]MemberDTO, 0, len(members))
	for _, member := range members {
		out = append(out, memberDTO(member))
	}
	http_utils.RespondList(w, out, total, opts.SortField, opts.SortDir)
}

// AddMember adds an organization member to a team.
func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	var req MemberRequest
	if !decode(w, r, &req) {
		return
	}
	member, authErr := h.service.AddMember(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), strings.TrimSpace(req.UserID), req.Role)
	if authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondCreated(w, memberDTO(member), nil)
}

// UpdateMember changes a member's role.
func (h *Handler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	var req MemberRequest
	if !decode(w, r, &req) {
		return
	}
	if authErr := h.service.ChangeMemberRole(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), r.PathValue("userId"), req.Role); authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, map[string]string{"message": "role changed"}, nil)
}

// RemoveMember takes a user out of a team; members may remove themselves.
func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if authErr := h.service.RemoveMember(r.Context(), h.actor(r), r.PathValue("orgId"), r.PathValue("teamId"), r.PathValue("userId")); authErr != nil {
		fail(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, map[string]string{"message": "member removed"}, nil)
}
