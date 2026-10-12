package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *StatelessHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	err := h.StatelessService.Logout(ctx, userID)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Clear cookies
	h.clearTokenCookies(w)

	if emitErr := h.deps.Events.EmitAsync(ctx, types.EventAfterLogout, &types.LogoutEventData{
		UserID: userID,
	}); emitErr != nil {
		h.deps.Logger.Errorf("stateless: failed to emit after logout event: %v", emitErr)
	}

	http_utils.RespondSuccess(w, dto.MessageResponse{
		Message: "Logged out successfully",
		Success: true,
	}, nil)
}

func (h *StatelessHandler) clearTokenCookies(w http.ResponseWriter) {
	http_utils.ClearCredentialCookies(w, h.deps.Config.Security)
}
