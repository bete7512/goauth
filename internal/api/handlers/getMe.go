package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleGetMe handles getting current user information
func (h *AuthHandler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}
