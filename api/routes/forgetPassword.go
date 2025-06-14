package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/utils"
)

// HandleForgotPassword handles password reset requests
func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
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
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
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
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, resetToken, models.PasswordResetToken, 1*time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save reset token", err)
		return
	}

	// Send reset email
	if h.Auth.Config.EmailSender != nil {
		resetURL := fmt.Sprintf("%s?token=%s&email=%s",
			h.Auth.Config.AuthConfig.PasswordResetURL,
			resetToken,
			user.Email)

		err = h.Auth.Config.EmailSender.SendPasswordReset(*user, resetURL)
		if err != nil {
			// fmt.Printf("Failed to send password reset email: %v\n", err)
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
