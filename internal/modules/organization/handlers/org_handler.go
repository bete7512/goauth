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

type OrgHandler struct {
	deps       config.ModuleDependencies
	orgService services.OrgService
}

func NewOrgHandler(deps config.ModuleDependencies, orgService services.OrgService) *OrgHandler {
	return &OrgHandler{deps: deps, orgService: orgService}
}

func (h *OrgHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Authentication required")
		return
	}

	var req dto.CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	org, authErr := h.orgService.Create(r.Context(), userID, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondCreated(w, dto.OrgToDTO(org), nil)
}

func (h *OrgHandler) MyOrgs(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Authentication required")
		return
	}

	orgs, authErr := h.orgService.ListByUser(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, dto.OrgsToDTO(orgs), nil)
}

func (h *OrgHandler) Get(w http.ResponseWriter, r *http.Request) {
	org, ok := r.Context().Value(types.OrgKey).(*models.Organization)
	if !ok || org == nil {
		http_utils.RespondError(w, http.StatusNotFound, string(types.ErrOrgNotFound), "Organization not found")
		return
	}
	http_utils.RespondSuccess(w, dto.OrgToDTO(org), nil)
}

func (h *OrgHandler) Update(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleAdmin) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Insufficient role")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)

	var req dto.UpdateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	org, authErr := h.orgService.Update(r.Context(), orgID, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, dto.OrgToDTO(org), nil)
}

func (h *OrgHandler) Delete(w http.ResponseWriter, r *http.Request) {
	role, _ := r.Context().Value(types.OrgRoleKey).(string)
	if !types.HasMinimumRole(role, types.OrgRoleOwner) {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrOrgInsufficientRole), "Only the owner can delete the organization")
		return
	}

	orgID, _ := r.Context().Value(types.OrgIDKey).(string)

	if authErr := h.orgService.Delete(r.Context(), orgID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess[any](w, nil, nil)
}

func (h *OrgHandler) Switch(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(types.UserIDKey).(string)
	user, _ := r.Context().Value(types.UserKey).(*models.User)
	if user == nil {
		userRepo := h.deps.Storage.Core().Users()
		var err error
		user, err = userRepo.FindByID(r.Context(), userID)
		if err != nil || user == nil {
			http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not found")
			return
		}
	}

	var req dto.SwitchOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "Invalid request body")
		return
	}
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	accessToken, refreshToken, authErr := h.orgService.SwitchOrg(r.Context(), user, req.OrgID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, &dto.SwitchOrgResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil)
}
