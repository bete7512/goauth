package routes

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/utils"
)

// HandleSendPhoneVerification handles sending phone verification code
func (h *AuthHandler) HandleSendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req struct {
		PhoneNumber string `json:"phone_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if req.PhoneNumber == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Phone number is required", nil)
		return
	}

	// Get user ID from authenticated request
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.JWTSecret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
		return
	}
	if user == nil {
		user, err = h.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(req.PhoneNumber)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
			return
		}
		if user == nil {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", nil)
			return
		}
	}

	if user.PhoneNumber == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Phone number not found", nil)
		return
	}

	if user.PhoneVerified {
		utils.RespondWithError(w, http.StatusBadRequest, "Phone number is already verified", nil)
		return
	}

	// Generate verification code
	OTP, err := h.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate verification code", nil)
		return
	}

	hashedOTP, err := h.Auth.TokenManager.HashToken(OTP)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to hash verification code", nil)
		return
	}

	// Save verification code
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, hashedOTP, models.PhoneVerificationToken, h.Auth.Config.PhoneVerificationTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification code", nil)
		return
	}

	// Send verification SMS
	if h.Auth.Config.SMSSender != nil {
		err = h.Auth.Config.SMSSender.SendTwoFactorCode(*user, OTP)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send verification SMS", nil)
			return
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Verification code sent successfully",
	})
}
