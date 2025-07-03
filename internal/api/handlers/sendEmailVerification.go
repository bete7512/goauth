package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

// HandleSendEmailVerification handles sending email verification
func (h *AuthHandler) HandleSendEmailVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.authService.SendEmailVerification(r.Context(), userID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send email verification", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "email verification sent"})
}
