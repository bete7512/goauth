package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleForgotPassword handles password reset requests
func (h *AuthRoutes) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req schemas.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Check if user exists
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}

	// Generate reset token
	resetToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate reset token", err)
		return
	}
	// Save reset token
	err = h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, resetToken, types.PasswordResetToken, 1*time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save reset token", err)
		return
	}

	// Send reset email
	resetURL := fmt.Sprintf("%s?token=%s&email=%s",
		h.Auth.Config.AuthConfig.Methods.EmailVerification.VerificationURL,
		resetToken,
		user.Email)
	if h.Auth.Config.Email.Sender.CustomSender != nil {
		err = h.Auth.Config.Email.Sender.CustomSender.SendPasswordResetEmail(r.Context(), *user, resetURL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send password reset email", err)
			return
		}
	}
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "If your email address exists in our database, you will receive a password recovery link at your email address shortly.",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}

}
