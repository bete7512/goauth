package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ListSessions returns all active sessions for the authenticated user
func (h *SessionHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	opts := models.SessionListOpts{ListingOpts: http_utils.ParseListingOpts(r)}
	opts.Normalize(100)

	// Try to get current session ID from the refresh token cookie
	currentSessionID := ""
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	if cookie, err := r.Cookie(refreshTokenName); err == nil && cookie.Value != "" {
		session, svcErr := h.service.FindSessionByToken(ctx, cookie.Value)
		if svcErr == nil && session != nil {
			currentSessionID = session.ID
		}
	}

	sessions, total, svcErr := h.service.ListSessions(ctx, userID, currentSessionID, opts)
	if svcErr != nil {
		http_utils.RespondError(w, svcErr.StatusCode, string(svcErr.Code), svcErr.Message)
		return
	}

	http_utils.RespondList[dto.SessionDTO](w, sessions, total, opts.SortField, opts.SortDir)
}

// GetSession returns a specific session by ID
func (h *SessionHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	// Extract session ID from URL path
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Session ID is required")
		return
	}

	response, err := h.service.GetSession(ctx, userID, sessionID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// DeleteSession deletes a specific session by ID
func (h *SessionHandler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	sessionID := r.PathValue("session_id")
	// Extract session ID from URL path
	if sessionID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Session ID is required")
		return
	}

	err := h.service.DeleteSession(ctx, userID, sessionID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	http_utils.RespondSuccess(w, map[string]interface{}{
		"message": "Session deleted successfully",
	}, nil)
}

// DeleteAllSessions deletes all sessions for the authenticated user
func (h *SessionHandler) DeleteAllSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	err := h.service.DeleteAllSessions(ctx, userID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Clear cookies
	h.clearSessionCookies(w)

	http_utils.RespondSuccess(w, map[string]interface{}{
		"message": "All sessions deleted successfully",
	}, nil)
}
