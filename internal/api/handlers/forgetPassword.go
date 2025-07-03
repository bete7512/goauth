package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleForgotPassword handles password reset request
func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.ForgotPassword(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to process request", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "password reset email sent"})
}
