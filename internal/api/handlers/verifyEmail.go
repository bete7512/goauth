package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleVerifyEmail handles email verification
func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {

	var req dto.EmailVerificationRequest
	if r.Method == http.MethodGet {
		// get token and email
		token := r.URL.Query().Get("token")
		email := r.URL.Query().Get("email")
		if token == "" || email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "token and email are required", nil)
			return
		}
		req = dto.EmailVerificationRequest{
			Token: token,
			Email: email,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
			return
		}
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.VerifyEmail(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "email verified successfully"})
}
