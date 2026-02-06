package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/audit/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
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
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth}, // Requires authentication
		},
		{
			Name:        string(types.RouteAuditMyLogins),
			Path:        "/me/audit/logins",
			Method:      http.MethodGet,
			Handler:     h.GetMyLogins,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        string(types.RouteAuditMyChanges),
			Path:        "/me/audit/changes",
			Method:      http.MethodGet,
			Handler:     h.GetMyChanges,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        string(types.RouteAuditMySecurity),
			Path:        "/me/audit/security",
			Method:      http.MethodGet,
			Handler:     h.GetMySecurity,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},

		// Admin routes
		{
			Name:        string(types.RouteAdminListAuditLogs),
			Path:        "/admin/audit",
			Method:      http.MethodGet,
			Handler:     h.AdminListAuditLogs,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminGetUserAudit),
			Path:        "/admin/audit/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetUserAudit,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminGetActionAudit),
			Path:        "/admin/audit/actions/{action}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetActionAudit,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
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

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetMyAuditLogs(r.Context(), userID, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// GetMyLogins handles GET /me/audit/logins
func (h *AuditHandler) GetMyLogins(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetMyLogins(r.Context(), userID, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// GetMyChanges handles GET /me/audit/changes
func (h *AuditHandler) GetMyChanges(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetMyChanges(r.Context(), userID, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// GetMySecurity handles GET /me/audit/security
func (h *AuditHandler) GetMySecurity(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetMySecurity(r.Context(), userID, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// Admin handlers

// AdminListAuditLogs handles GET /admin/audit
func (h *AuditHandler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.ListAllAuditLogs(r.Context(), opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// AdminGetUserAudit handles GET /admin/audit/users/{id}
func (h *AuditHandler) AdminGetUserAudit(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, "bad_request", "user ID is required")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetUserAuditLogs(r.Context(), userID, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// AdminGetActionAudit handles GET /admin/audit/actions/{action}
func (h *AuditHandler) AdminGetActionAudit(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "" {
		http_utils.RespondError(w, http.StatusBadRequest, "bad_request", "action is required")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, err := h.service.GetAuditLogsByAction(r.Context(), action, opts)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}
