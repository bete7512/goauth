package handlers

import (
	"net/http"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *SessionHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	sessionID, _ := ctx.Value(types.SessionIDKey).(string)
	if sessionID == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Session ID not found")
		return
	}

	err := h.service.Logout(ctx, userID, sessionID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Clear cookies
	h.clearSessionCookies(w)

	if emitErr := h.deps.Events.EmitAsync(ctx, types.EventAfterLogout, &types.LogoutEventData{
		UserID: userID,
	}); emitErr != nil {
		h.deps.Logger.Errorf("session: failed to emit after logout event: %v", emitErr)
	}

	http_utils.RespondSuccess(w, map[string]interface{}{
		"message": "Logged out successfully",
	}, nil)
}

func (h *SessionHandler) clearSessionCookies(w http.ResponseWriter) {
	sessionCfg := h.deps.Config.Security.Session

	accessTokenName := "goauth_access_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    "",
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   -1,
	})
	refreshTokenName := "goauth_refresh_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    "",
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   -1,
	})

	// Clear session cache cookie
	if h.encoder != nil {
		http.SetCookie(w, &http.Cookie{
			Name:     "goauth_session_" + sessionCfg.Name,
			Value:    "",
			HttpOnly: true,
			Secure:   sessionCfg.Secure,
			SameSite: sessionCfg.SameSite,
			Path:     sessionCfg.Path,
			MaxAge:   -1,
		})
	}
}
