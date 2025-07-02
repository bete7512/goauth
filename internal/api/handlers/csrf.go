package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleGetCSRFToken generates and returns a CSRF token for the authenticated user
func (h *AuthRoutes) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from request context (set by auth middleware)
	userID := r.Context().Value("user_id")
	if userID == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "user not authenticated", nil)
		return
	}

	// Generate CSRF token
	token, err := h.Auth.CSRFManager.GenerateToken(r.Context(), userID.(string))
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate csrf token", err)
		return
	}

	// Return the token
	response := map[string]interface{}{
		"csrf_token": token,
	}

	if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
	}
}
