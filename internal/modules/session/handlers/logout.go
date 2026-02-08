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

	err := h.SessionService.Logout(ctx, userID)
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
	accessTokenName := "goauth_access_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    "",
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure,
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   -1,
	})
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    "",
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure,
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   -1,
	})
}
