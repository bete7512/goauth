package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/invitation/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/invitation/services"
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

func (h *InvitationHandler) Send(w http.ResponseWriter, r *http.Request) {
	inviterID, _ := r.Context().Value(types.UserIDKey).(string)

	var req dto.SendInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	invitation, authErr := h.invitationService.Send(r.Context(), &req, inviterID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondCreated(w, dto.InvitationToDTO(invitation), nil)
}

func (h *InvitationHandler) List(w http.ResponseWriter, r *http.Request) {
	inviterID, _ := r.Context().Value(types.UserIDKey).(string)

	opts := models.InvitationListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Status:      r.URL.Query().Get("status"),
		Purpose:     r.URL.Query().Get("purpose"),
	}
	opts.Normalize(100)

	invitations, total, authErr := h.invitationService.List(r.Context(), inviterID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, dto.InvitationsToDTO(invitations), total, opts.SortField, opts.SortDir)
}

func (h *InvitationHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	inviterID, _ := r.Context().Value(types.UserIDKey).(string)
	invID := extractLastPathSegment(r.URL.Path)

	if authErr := h.invitationService.Cancel(r.Context(), invID, inviterID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *InvitationHandler) Accept(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)

	userRepo := h.deps.Storage.Core().Users()
	user, err := userRepo.FindByID(r.Context(), userID)
	if err != nil || user == nil {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not found")
		return
	}

	var req dto.AcceptInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if authErr := h.invitationService.Accept(r.Context(), userID, user.Email, req.Token); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *InvitationHandler) Decline(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)

	var req dto.DeclineInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if authErr := h.invitationService.Decline(r.Context(), userID, req.Token); authErr != nil {
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

func extractLastPathSegment(path string) string {
	parts := strings.Split(strings.TrimRight(path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
