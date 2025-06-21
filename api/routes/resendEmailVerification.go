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

func (h *AuthHandler) HandleResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if !h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup {
		utils.RespondWithError(w, http.StatusBadRequest, "Email verification is not enabled", nil)
		return
	}

	var req schemas.ResendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
			"message": "If your email address exists in our database, you will receive a verification email shortly.",
		})
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
			return
		}
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}

	// Check if already verified
	if user.EmailVerified {

		err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
			"message": "Email already verified.",
		})
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
			return
		}
		return
	}

	// Generate verification token
	verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate verification token", err)
		return
	}

	// Save verification token (valid for 24 hours)
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, verificationToken, models.EmailVerificationToken, 24*time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification token", err)
		return
	}

	// Send verification email
	if h.Auth.Config.EmailSender != nil {
		verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
			h.Auth.Config.AuthConfig.EmailVerificationURL,
			verificationToken,
			user.Email)

		err = h.Auth.Config.EmailSender.SendVerification(*user, verificationURL)
		if err != nil {
			fmt.Printf("Failed to send verification email: %v\n", err)
		}
	}
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "If your email address exists in our database, you will receive a verification email shortly.",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}
