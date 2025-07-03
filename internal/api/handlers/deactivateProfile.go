package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleDeactivateUser handles user account deactivation
func (h *AuthHandler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.DeactivateUserRequest
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
	if err := h.authService.DeactivateUser(r.Context(), userID, &req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Clear cookies after deactivation
	clearAuthCookies(w)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "account deactivated successfully"})
}
