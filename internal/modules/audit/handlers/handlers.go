package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/internal/modules/audit/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type AuditHandler struct {
	deps    config.ModuleDependencies
	service *services.AuditService
}

func NewAuditHandler(deps config.ModuleDependencies, service *services.AuditService) *AuditHandler {
	return &AuditHandler{
		deps:    deps,
		service: service,
	}
}

// GetRoutes returns all audit routes
func (h *AuditHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		// User self-service routes
		{
			Name:        string(types.RouteAuditMyLogs),
			Path:        "/me/audit",
			Method:      http.MethodGet,
			Handler:     h.GetMyAuditLogs,
			Middlewares: []string{string(types.MiddlewareAuth)}, // Requires authentication
		},
		{
			Name:        string(types.RouteAuditMyLogins),
			Path:        "/me/audit/logins",
			Method:      http.MethodGet,
			Handler:     h.GetMyLogins,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteAuditMyChanges),
			Path:        "/me/audit/changes",
			Method:      http.MethodGet,
			Handler:     h.GetMyChanges,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteAuditMySecurity),
			Path:        "/me/audit/security",
			Method:      http.MethodGet,
			Handler:     h.GetMySecurity,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},

		// Admin routes
		{
			Name:        string(types.RouteAdminListAuditLogs),
			Path:        "/admin/audit",
			Method:      http.MethodGet,
			Handler:     h.AdminListAuditLogs,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminGetUserAudit),
			Path:        "/admin/audit/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetUserAudit,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
		{
			Name:        string(types.RouteAdminGetActionAudit),
			Path:        "/admin/audit/actions/{action}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetActionAudit,
			Middlewares: []string{string(types.MiddlewareAuth), string(types.MiddlewareAdminAuth)},
		},
	}
}

// User self-service handlers

// GetMyAuditLogs handles GET /me/audit
func (h *AuditHandler) GetMyAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetMyAuditLogs(r.Context(), userID, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// GetMyLogins handles GET /me/audit/logins
func (h *AuditHandler) GetMyLogins(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetMyLogins(r.Context(), userID, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// GetMyChanges handles GET /me/audit/changes
func (h *AuditHandler) GetMyChanges(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetMyChanges(r.Context(), userID, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// GetMySecurity handles GET /me/audit/security
func (h *AuditHandler) GetMySecurity(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetMySecurity(r.Context(), userID, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// Admin handlers

// AdminListAuditLogs handles GET /admin/audit
func (h *AuditHandler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := h.getPagination(r)

	logs, err := h.service.ListAllAuditLogs(r.Context(), limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	})
}

// AdminGetUserAudit handles GET /admin/audit/users/{id}
func (h *AuditHandler) AdminGetUserAudit(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, "bad_request", "user ID is required")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetUserAuditLogs(r.Context(), userID, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
		"logs":    logs,
		"count":   len(logs),
	})
}

// AdminGetActionAudit handles GET /admin/audit/actions/{action}
func (h *AuditHandler) AdminGetActionAudit(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "" {
		http_utils.RespondError(w, http.StatusBadRequest, "bad_request", "action is required")
		return
	}

	limit, offset := h.getPagination(r)

	logs, err := h.service.GetAuditLogsByAction(r.Context(), action, limit, offset)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"action": action,
		"logs":   logs,
		"count":  len(logs),
	})
}

// Helper method to get pagination parameters
func (h *AuditHandler) getPagination(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))

	if limit == 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100 // Max 100 records per request
	}

	return limit, offset
}
