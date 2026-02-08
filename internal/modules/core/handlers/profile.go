package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// UpdateProfile handles PUT /profile
func (h *CoreHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "User not authenticated")
		return
	}

	var req dto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Update profile via service
	userDTO, authErr := h.coreService.UpdateProfile(ctx, userID, &req)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Collect updated fields for event
	var updatedFields []string
	if req.Name != "" {
		updatedFields = append(updatedFields, "name")
	}
	if req.Phone != "" {
		updatedFields = append(updatedFields, "phone")
	}
	if req.Avatar != "" {
		updatedFields = append(updatedFields, "avatar")
	}

	// Emit profile change event
	h.deps.Events.EmitAsync(ctx, types.EventAfterChangeProfile, &types.ProfileChangedData{
		UserID: userID,
		Fields: updatedFields,
	})

	http_utils.RespondSuccess(w, userDTO, nil)
}
