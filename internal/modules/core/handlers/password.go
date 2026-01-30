package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// ChangePassword handles PUT /change-password
func (h *CoreHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated")
		return
	}

	var req dto.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", err.Error())
		return
	}

	// Call service
	response, err := h.CoreService.ChangePassword(ctx, userID, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}


	// logout
	

	http_utils.RespondSuccess(w, response, nil)
}
