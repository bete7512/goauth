package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/pkg/config"
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
			Middlewares: []string{string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminGetUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.GetUser,
			Middlewares: []string{string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminUpdateUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodPut,
			Handler:     h.UpdateUser,
			Middlewares: []string{string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminDeleteUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodDelete,
			Handler:     h.DeleteUser,
			Middlewares: []string{string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminUserAuditLogs),
			Path:        "/admin/users/{id}/audit",
			Method:      http.MethodGet,
			Handler:     h.GetUserAuditLogs,
			Middlewares: []string{string(types.MiddlewareAdminAuth)},
		},
	}
}

// ListUsers handles GET /admin/users
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit == 0 {
		limit = 20
	}

	users, err := h.service.ListUsers(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
		"count": len(users),
	})
}

// GetUser handles GET /admin/users/{id}
func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// UpdateUser handles PUT /admin/users/{id}
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User updated successfully",
		"user":    user,
	})
}

// DeleteUser handles DELETE /admin/users/{id}
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	if err := h.service.DeleteUser(r.Context(), userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User deleted successfully",
	})
}

// GetUserAuditLogs handles GET /admin/users/{id}/audit
func (h *AdminHandler) GetUserAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit == 0 {
		limit = 50
	}

	logs, err := h.service.GetUserAuditLogs(r.Context(), userID, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}
