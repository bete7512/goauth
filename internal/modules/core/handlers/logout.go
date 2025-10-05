package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
)

func (h *CoreHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: Get user ID from context (set by auth middleware)
	// userID := ctx.Value("user_id").(string)
	// sessionID := ctx.Value("session_id").(string)

	// Emit BEFORE logout event
	if err := h.deps.Events.EmitSync(ctx, "before:logout", map[string]interface{}{
		"user_id": "user-123",
	}); err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "LOGOUT_FAILED", "Logout failed: "+err.Error())
		return
	}

	// TODO: Implement logout logic
	// 1. Get session from token
	// 2. Delete/invalidate session
	// 3. Clear cookies

	// Emit AFTER logout event
	h.deps.Events.Emit(ctx, "after:logout", map[string]interface{}{
		"user_id": "user-123",
	})

	http_utils.RespondSuccess(w, dto.MessageResponse{
		Message: "Logout successful",
		Success: true,
	}, nil)
}
