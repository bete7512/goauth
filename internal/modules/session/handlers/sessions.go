package handlers

import (
	"net/http"
	"strings"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
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

	// Try to get current session ID from the refresh token cookie
	currentSessionID := ""
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	if cookie, err := r.Cookie(refreshTokenName); err == nil && cookie.Value != "" {
		session, err := h.SessionService.SessionRepository.FindByToken(ctx, cookie.Value)
		if err == nil && session != nil {
			currentSessionID = session.ID
		}
	}

	response, err := h.SessionService.ListSessions(ctx, userID, currentSessionID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
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
	sessionID := extractPathParam(r.URL.Path, "/sessions/")
	if sessionID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Session ID is required")
		return
	}

	response, err := h.SessionService.GetSession(ctx, userID, sessionID)
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

	// Extract session ID from URL path
	sessionID := extractPathParam(r.URL.Path, "/sessions/")
	if sessionID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Session ID is required")
		return
	}

	err := h.SessionService.DeleteSession(ctx, userID, sessionID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	http_utils.RespondSuccess(w, map[string]interface{}{
		"message": "Session deleted successfully",
		"success": true,
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

	err := h.SessionService.DeleteAllSessions(ctx, userID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Clear cookies
	h.clearSessionCookies(w)

	http_utils.RespondSuccess(w, map[string]interface{}{
		"message": "All sessions deleted successfully",
		"success": true,
	}, nil)
}

// extractPathParam extracts a path parameter from URL
// e.g., extractPathParam("/auth/sessions/123", "/sessions/") returns "123"
func extractPathParam(path, prefix string) string {
	idx := strings.LastIndex(path, prefix)
	if idx == -1 {
		return ""
	}
	param := path[idx+len(prefix):]
	// Remove trailing slash if present
	param = strings.TrimSuffix(param, "/")
	return param
}

