package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleSendEmailVerification handles sending email verification
func (h *AuthHandler) HandleSendEmailVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	var req dto.SendEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Call service
	if err := h.authService.SendEmailVerification(r.Context(), req.Email); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send email verification", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "email verification sent"})
}
