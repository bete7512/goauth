package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *AuthRoutes) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// if !h.Auth.Config.AuthConfig.Methods.TwoFactorMethod {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
	// 	return
	// }

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		// utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "internal server error", err)
		return
	}

	// Send two-factor code
	err = h.sendTwoFactorCode(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send two-factor code: "+err.Error(), err)

		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":           "two-factor verification code sent",
		"two_factor_method": h.Auth.Config.AuthConfig.Methods.TwoFactorMethod,
	})

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
		return
	}
}

func (h *AuthRoutes) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// if !h.Auth.Config.AuthConfig.Methods. {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
	// 	return
	// }

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.VerifyTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "internal server error", err)
		return
	}

	// Validate two-factor code
	// valid, err := h.Auth.Repository.GetTokenRepository().ValidateTokenWithUserID(user.ID, req.Code, types.TwoFactorCode)
	// if err != nil || !valid {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Invalid two-factor code", err)
	// 	return
	// }

	// Enable two-factor authentication
	twoFactorEnabled := true
	user.TwoFactorEnabled = &twoFactorEnabled
	// user.TwoFactorVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to enable two-factor authentication: "+err.Error(), err)
		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "two-factor authentication enabled successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
		return
	}
}

// HandleDisableTwoFactor disables two-factor authentication
func (h *AuthRoutes) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.DisableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "internal server error", err)
		return
	}

	// Verify password
	err = h.Auth.TokenManager.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Password is incorrect", err)

		return
	}

	// Disable two-factor authentication
	twoFactorEnabled := false
	user.TwoFactorEnabled = &twoFactorEnabled
	// user.TwoFactorVerified = false
	err = h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to disable two-factor authentication: "+err.Error(), err)
		return
	}

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Two-factor authentication disabled successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
		return
	}
}

// sendTwoFactorCode sends a two-factor verification code
func (h *AuthRoutes) sendTwoFactorCode(ctx context.Context, user *types.User) error {
	// Generate random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Save code (valid for 10 minutes)
	err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, code, types.TwoFactorCode, 10*time.Minute)
	if err != nil {
		return err
	}

	// Send code via configured method
	if h.Auth.Config.AuthConfig.Methods.TwoFactorMethod == "email" && h.Auth.Config.Email.Sender.CustomSender != nil {
		return h.Auth.Config.Email.Sender.CustomSender.SendTwoFactorEmail(ctx, *user, code)
	} else if h.Auth.Config.AuthConfig.Methods.TwoFactorMethod == "sms" && h.Auth.Config.SMS.CustomSender != nil {
		// Assuming user has a phone number
		return h.Auth.Config.SMS.CustomSender.SendTwoFactorSMS(ctx, *user, code)
	}

	return errors.New("no valid two-factor delivery method configured")
}
