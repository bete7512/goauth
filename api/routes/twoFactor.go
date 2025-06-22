package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/utils"
	"gorm.io/gorm"
)

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *AuthHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// if !h.Auth.Config.AuthConfig.Methods.TwoFactorMethod {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
	// 	return
	// }

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		// utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
		return
	}

	// Send two-factor code
	err = h.sendTwoFactorCode(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send two-factor code: "+err.Error(), err)

		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":           "Two-factor verification code sent",
		"two_factor_method": h.Auth.Config.AuthConfig.Methods.TwoFactorMethod,
	})

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

func (h *AuthHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// if !h.Auth.Config.AuthConfig.Methods. {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
	// 	return
	// }

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.VerifyTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
		return
	}

	// Validate two-factor code
	// valid, err := h.Auth.Repository.GetTokenRepository().ValidateTokenWithUserID(user.ID, req.Code, models.TwoFactorCode)
	// if err != nil || !valid {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Invalid two-factor code", err)
	// 	return
	// }

	// Enable two-factor authentication
	user.TwoFactorEnabled = true
	// user.TwoFactorVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to enable two-factor authentication: "+err.Error(), err)
		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Two-factor authentication enabled successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleDisableTwoFactor disables two-factor authentication
func (h *AuthHandler) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.DisableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
		return
	}

	// Verify password
	err = h.Auth.TokenManager.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Password is incorrect", err)

		return
	}

	// Disable two-factor authentication
	user.TwoFactorEnabled = false
	// user.TwoFactorVerified = false
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to disable two-factor authentication: "+err.Error(), err)
		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Two-factor authentication disabled successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// sendTwoFactorCode sends a two-factor verification code
func (h *AuthHandler) sendTwoFactorCode(user *models.User) error {
	// Generate random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Save code (valid for 10 minutes)
	err := h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, code, models.TwoFactorCode, 10*time.Minute)
	if err != nil {
		return err
	}

	// Send code via configured method
	if h.Auth.Config.AuthConfig.Methods.TwoFactorMethod == "email" && h.Auth.Config.Email.Sender.CustomSender != nil {
		return h.Auth.Config.Email.Sender.CustomSender.SendTwoFactorCode(*user, code)
	} else if h.Auth.Config.AuthConfig.Methods.TwoFactorMethod == "sms" && h.Auth.Config.SMS.CustomSender != nil {
		// Assuming user has a phone number
		return h.Auth.Config.SMS.CustomSender.SendTwoFactorCode(*user, code)
	}

	return errors.New("no valid two-factor delivery method configured")
}
