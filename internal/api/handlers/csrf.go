package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleGetCSRFToken generates and returns a CSRF token for the authenticated user
func (h *AuthHandler) HandleGetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Call service
	if err := h.authService.GetCSRFToken(r.Context()); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "CSRF token generated"})
}
