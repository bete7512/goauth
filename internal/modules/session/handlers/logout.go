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
	http_utils.ClearCredentialCookies(w, h.deps.Config.Security)
}
