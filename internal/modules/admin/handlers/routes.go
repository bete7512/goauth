package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/admin/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ListUsers handles GET /admin/users
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	opts := models.UserListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Query:       r.URL.Query().Get("query"),
	}
	opts.Normalize(100)

	users, total, authErr := h.service.ListUsers(r.Context(), opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	userDTOs := dto.UsersToAdminDTO(users)
	http_utils.RespondList(w, userDTOs, total, opts.SortField, opts.SortDir)
}

// GetUser handles GET /admin/users/{id}
func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, authErr := h.service.GetUser(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	userDTO := dto.UserToAdminDTO(user)
	http_utils.RespondSuccess(w, userDTO, nil)
}

// UpdateUser handles PUT /admin/users/{id}
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, authErr := h.service.GetUser(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	var req dto.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	req.ApplyTo(user)

	if authErr := h.service.UpdateUser(r.Context(), user); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	userDTO := dto.UserToAdminDTO(user)
	http_utils.RespondSuccess(w, userDTO, nil)
}

// DeleteUser handles DELETE /admin/users/{id}
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	if authErr := h.service.DeleteUser(r.Context(), userID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, dto.MessageResponse{Message: "User deleted successfully"}, nil)
}
