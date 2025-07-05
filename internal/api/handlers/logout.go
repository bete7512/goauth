package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)
	sessionID := r.Context().Value("session_id").(string)

	// Call service
	if err := h.authService.Logout(r.Context(), userID, sessionID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "logout failed", err)
		return
	}

	// Clear cookies
	// clearAuthCookies(w)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "logout successful"})
}



// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)
	sessionID := r.Context().Value("session_id").(string)

	// Call service
	if err := h.authService.Logout(r.Context(), userID, sessionID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "logout failed", err)
		return
	}

	// Clear cookies
	// clearAuthCookies(w)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "logout successful"})
}