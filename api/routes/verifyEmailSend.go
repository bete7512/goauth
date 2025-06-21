package routes

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
)

// HandleResendEmailVerification handles resending email verification
func (h *AuthHandler) HandleResendEmailVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Get email from request body
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if req.Email == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}

	if user.EmailVerified {
		utils.RespondWithError(w, http.StatusBadRequest, "Email is already verified", nil)
		return
	}

	// Generate new verification token
	verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate verification token", nil)
		return
	}

	hashedVerificationToken, err := h.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to hash verification token", nil)
		return
	}
	// Save verification token
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, hashedVerificationToken, models.EmailVerificationToken, h.Auth.Config.EmailVerificationTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification token", nil)
		return
	}

	// Send verification email
	if h.Auth.Config.EmailSender != nil {
		verificationURL := h.Auth.Config.AuthConfig.EmailVerificationURL + "?token=" + verificationToken + "&email=" + user.Email
		err = h.Auth.Config.EmailSender.SendVerification(*user, verificationURL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send verification email", nil)
			return
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Verification email sent successfully",
	})
}
