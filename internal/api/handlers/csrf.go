package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
)

// HandleGetCSRFToken generates and returns a CSRF token for the authenticated user
func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	userID := r.Context().Value(config.UserIDKey).(string)
	// Call service
	token, err := h.authService.GetCSRFToken(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token generated", "token": token})
}
