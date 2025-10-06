package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Profile handles GET /profile (same as Me)
func (h *CoreHandler) Profile(w http.ResponseWriter, r *http.Request) {
	// Delegate to Me handler
	h.Me(w, r)
}

// UpdateProfile handles PUT /profile
func (h *CoreHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: Get user ID from context (set by auth middleware)
	// userID := ctx.Value("user_id").(string)

	var req dto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", err.Error())
		return
	}

	// TODO: Implement update profile logic
	// 1. Get user from database
	// 2. Update allowed fields
	// 3. Save to database
	// 4. Return updated user

	h.deps.Events.EmitAsync(ctx, types.EventAfterChangeProfile, map[string]interface{}{
		"user_id": "user-123",
		"fields":  []string{"name", "phone", "avatar"},
	})

	http_utils.RespondSuccess(w, dto.MessageResponse{
		Message: "Profile updated successfully",
		Success: true,
	}, nil)
}
