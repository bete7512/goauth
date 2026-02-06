package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/admin/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/admin/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type AdminHandler struct {
	deps    config.ModuleDependencies
	service *services.AdminService
}

func NewAdminHandler(deps config.ModuleDependencies, service *services.AdminService) *AdminHandler {
	return &AdminHandler{
		deps:    deps,
		service: service,
	}
}

// GetRoutes returns all admin routes
func (h *AdminHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:        string(types.RouteAdminListUsers),
			Path:        "/admin/users",
			Method:      http.MethodGet,
			Handler:     h.ListUsers,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminGetUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.GetUser,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminUpdateUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodPut,
			Handler:     h.UpdateUser,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminDeleteUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodDelete,
			Handler:     h.DeleteUser,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
	}
}

// ListUsers handles GET /admin/users
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	opts := models.UserListOpts{
		ListingOpts: http_utils.ParseListingOpts(r),
		Query:       r.URL.Query().Get("query"),
	}
	opts.Normalize(100)

	users, total, err := h.service.ListUsers(r.Context(), opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	userDTOs := dto.UsersToAdminDTO(users)
	http_utils.RespondList(w, userDTOs, total, opts.SortField, opts.SortDir)
}

// GetUser handles GET /admin/users/{id}
func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		http_utils.RespondError(w, http.StatusNotFound, "user_not_found", err.Error())
		return
	}

	userDTO := dto.UserToAdminDTO(user)
	http_utils.RespondSuccess(w, userDTO, nil)
}

// UpdateUser handles PUT /admin/users/{id}
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		http_utils.RespondError(w, http.StatusNotFound, "user_not_found", err.Error())
		return
	}

	var req dto.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	req.ApplyTo(user)

	if err := h.service.UpdateUser(r.Context(), user); err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	userDTO := dto.UserToAdminDTO(user)
	msg := "User updated successfully"
	http_utils.RespondSuccess(w, userDTO, &msg)
}

// DeleteUser handles DELETE /admin/users/{id}
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	if err := h.service.DeleteUser(r.Context(), userID); err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondSuccess(w, dto.MessageResponse{Message: "User deleted successfully"}, nil)
}
