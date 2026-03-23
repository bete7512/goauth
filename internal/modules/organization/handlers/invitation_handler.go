package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/organization/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type InvitationHandler struct {
	deps              config.ModuleDependencies
	invitationService services.InvitationService
}

func NewInvitationHandler(deps config.ModuleDependencies, invitationService services.InvitationService) *InvitationHandler {
	return &InvitationHandler{deps: deps, invitationService: invitationService}
}

func (h *InvitationHandler) Invite(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)
	inviterID, _ := r.Context().Value(types.UserIDKey).(string)

	var req services.InviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}

	invitation, authErr := h.invitationService.Invite(r.Context(), orgID, &req, inviterID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondCreated(w, invitation, nil)
}

func (h *InvitationHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)

	opts := models.InvitationListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Status:      r.URL.Query().Get("status"),
	}
	opts.Normalize(100)

	invitations, total, authErr := h.invitationService.ListInvitations(r.Context(), orgID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, invitations, total, opts.SortField, opts.SortDir)
}

func (h *InvitationHandler) CancelInvitation(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)
	invID := extractLastPathSegment(r.URL.Path)

	if authErr := h.invitationService.CancelInvitation(r.Context(), orgID, invID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *InvitationHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)

	// Get user email
	userRepo := h.deps.Storage.Core().Users()
	user, err := userRepo.FindByID(r.Context(), userID)
	if err != nil || user == nil {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not found")
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "token is required")
		return
	}

	member, authErr := h.invitationService.AcceptInvitation(r.Context(), userID, user.Email, req.Token)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, member, nil)
}

func (h *InvitationHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "token is required")
		return
	}

	if authErr := h.invitationService.DeclineInvitation(r.Context(), userID, req.Token); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *InvitationHandler) MyInvitations(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)

	userRepo := h.deps.Storage.Core().Users()
	user, err := userRepo.FindByID(r.Context(), userID)
	if err != nil || user == nil {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not found")
		return
	}

	invitations, authErr := h.invitationService.ListPendingByEmail(r.Context(), user.Email)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, invitations, nil)
}
