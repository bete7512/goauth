package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleUpdateProfile handles user profile updates
func (h *AuthHandler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.authService.UpdateProfile(r.Context(), userID, &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}
