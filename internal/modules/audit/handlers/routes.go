package handlers

import (
	"net/http"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// GetMyAuditLogs handles GET /me/audit
func (h *AuditHandler) GetMyAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user not authenticated")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, authErr := h.service.GetMyAuditLogs(r.Context(), userID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
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

	logs, total, authErr := h.service.GetMyLogins(r.Context(), userID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
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

	logs, total, authErr := h.service.GetMyChanges(r.Context(), userID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
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

	logs, total, authErr := h.service.GetMySecurity(r.Context(), userID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// AdminListAuditLogs handles GET /admin/audit
func (h *AuditHandler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, authErr := h.service.ListAllAuditLogs(r.Context(), opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// AdminGetUserAudit handles GET /admin/audit/users/{id}
func (h *AuditHandler) AdminGetUserAudit(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "user ID is required")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, authErr := h.service.GetUserAuditLogs(r.Context(), userID, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}

// AdminGetActionAudit handles GET /admin/audit/actions/{action}
func (h *AuditHandler) AdminGetActionAudit(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "action is required")
		return
	}

	opts := models.AuditLogListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	logs, total, authErr := h.service.GetAuditLogsByAction(r.Context(), action, opts)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondList(w, logs, total, opts.SortField, opts.SortDir)
}
