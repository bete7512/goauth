package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "user id not found in request")
		return
	}

	// Emit BEFORE logout event
	if err := h.deps.Events.EmitSync(ctx, types.EventBeforeLogout, map[string]interface{}{
		"user_id": userID,
	}); err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Logout failed: "+err.Error())
		return
	}

	// 1. Get session from token
	err := h.CoreService.Logout(ctx, userID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	accessTokenName := "goauth_access_" + h.deps.Config.Security.Session.Name
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:   accessTokenName,
		Value:  "",
		MaxAge: 0,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   refreshTokenName,
		Value:  "",
		MaxAge: 0,
	})
	// // Emit AFTER logout event
	// h.deps.Events.EmitAsync(ctx, types.EventAfterLogout, map[string]interface{}{
	// 	"user_id": "user-123",
	// })

	http_utils.RespondSuccess(w, dto.MessageResponse{
		Message: "Logout successful",
		Success: true,
	}, nil)
}
