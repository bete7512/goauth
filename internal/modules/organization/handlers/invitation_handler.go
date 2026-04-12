package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"
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

	var req dto.InviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	invitation, authErr := h.invitationService.Invite(r.Context(), orgID, &req, inviterID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondCreated(w, dto.InvitationToDTO(invitation), nil)
}

func (h *InvitationHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)

	opts := models.OrgInvitationListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Status:      r.URL.Query().Get("status"),
	}
	opts.Normalize(100)

	invitations, total, authErr := h.invitationService.ListInvitations(r.Context(), orgID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, dto.InvitationsToDTO(invitations), total, opts.SortField, opts.SortDir)
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

// AcceptInvitation is a PUBLIC endpoint (no auth required). The invitation token is the authorization.
// For new users: creates the account with the provided name/password.
// For existing users: just creates the org membership.
// Returns auth tokens and membership details.
func (h *InvitationHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req dto.AcceptInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	result, authErr := h.invitationService.AcceptInvitation(r.Context(), req.Token, req.Name, req.Password)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	accessToken, refreshToken, err := h.deps.SecurityManager.GenerateTokens(result.User, nil)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate tokens")
		return
	}

	http_utils.RespondSuccess(w, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": map[string]any{
			"id":             result.User.ID,
			"email":          result.User.Email,
			"name":           result.User.Name,
			"email_verified": result.User.EmailVerified,
		},
		"member":      dto.MemberCreatedToDTO(result.Member),
		"is_new_user": result.IsNewUser,
	}, nil)
}

// DeclineInvitation is a PUBLIC endpoint (no auth required). The invitation token is the authorization.
func (h *InvitationHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	var req dto.DeclineInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if authErr := h.invitationService.DeclineInvitation(r.Context(), req.Token); authErr != nil {
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

	http_utils.RespondSuccess(w, dto.InvitationsToDTO(invitations), nil)
}
