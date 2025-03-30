package handlers

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

	// Generate reset token
	resetToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate reset token", err)
		return
	}
	// Save reset token
	err = h.Auth.Repository.GetTokenRepository().SavePasswordResetToken(user.ID, resetToken, 1*time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save reset token", err)
		return
	}

	// Send reset email
	if h.Auth.Config.EmailSender != nil {
		resetURL := fmt.Sprintf("%s?token=%s&email=%s",
			h.Auth.Config.PasswordResetURL,
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

// HandleResetPassword handles password reset
func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var req schemas.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Validate token
	valid, userID, err := h.Auth.Repository.GetTokenRepository().ValidatePasswordResetToken(req.Token)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		return
	}

	// Validate password against policy
	if err := h.validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword, h.Auth.Config.PasswordPolicy.HashSaltLength)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to secure password: "+err.Error(), err)
		return
	}

	// Update password
	user.Password = hashedPassword
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update password: "+err.Error(), err)
		return
	}

	// Invalidate token
	err = h.Auth.Repository.GetTokenRepository().InvalidatePasswordResetToken(req.Token)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate token: "+err.Error(), err)
		return
	}

	// Invalidate all refresh tokens for security
	err = h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens: "+err.Error(), err)
		return
	}

	// Clear cookie
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully. Please log in with your new password.",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleUpdateUser handles user profile updates
func (h *AuthHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Get current user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
		return
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}

	// Update user
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update user: "+err.Error(), err)
		return
	}

	// Prepare user response
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	// json.NewEncoder(w).Encode(map[string]interface{}{
	// 	"user":    userResponse,
	// 	"message": "User updated successfully",
	// })
	err = utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"user":    userResponse,
		"message": "User updated successfully",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleDeactivateUser handles user account deactivation
func (h *AuthHandler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error(), nil)
		return
	}

	var req schemas.DeactivateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
		return
	}

	// Get current user
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
	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Password is incorrect", err)
		return
	}

	// Deactivate user
	user.Active = false
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to deactivate account: "+err.Error(), err)
		return
	}

	// Invalidate all refresh tokens
	err = h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens: "+err.Error(), err)
		return
	}
	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.Cookie.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	// json.NewEncoder(w).Encode(map[string]string{
	// 	"message": "Account deactivated successfully",
	// })

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Account deactivated successfully",
	})

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *AuthHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if !h.Auth.Config.EnableTwoFactor {
		utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
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
		"two_factor_method": h.Auth.Config.TwoFactorMethod,
	})

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleVerifyTwoFactor verifies two-factor code and enables 2FA
func (h *AuthHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if !h.Auth.Config.EnableTwoFactor {
		utils.RespondWithError(w, http.StatusBadRequest, "Two-factor authentication is not enabled", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
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
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTwoFactorCode(user.ID, req.Code)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid two-factor code", err)
		return
	}

	// Enable two-factor authentication
	user.TwoFactorEnabled = true
	user.TwoFactorVerified = true
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
	userID, err := h.authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
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
	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Password is incorrect", err)

		return
	}

	// Disable two-factor authentication
	user.TwoFactorEnabled = false
	user.TwoFactorVerified = false
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

// HandleVerifyEmail verifies user's email
func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	var token, email string
	if r.Method == http.MethodGet {
		token = r.URL.Query().Get("token")
		email = r.URL.Query().Get("email")
	} else {
		var req schemas.VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
			return
		}
		token = req.Token
		email = req.Email
	}

	if token == "" || email == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Missing token or email", nil)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.RespondWithError(w, http.StatusBadRequest, "User not found", err)
			return
		}
		utils.RespondWithError(w, http.StatusBadRequest, "Internal server error", err)
		return
	}

	// Validate verification token
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateEmailVerificationToken(user.ID, token)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid or expired verification token", err)
		return
	}

	// Mark email as verified
	user.EmailVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to verify email: "+err.Error(), err)
		return
	}

	// Invalidate verification token
	err = h.Auth.Repository.GetTokenRepository().InvalidateEmailVerificationToken(user.ID, token)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate verification token: "+err.Error(), err)
		return
	}

	// Generate tokens if needed
	var response map[string]interface{}
	if r.Method == http.MethodPost {
		accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.Cookie.AccessTokenTTL, h.Auth.Config.Cookie.RefreshTokenTTL, h.Auth.Config.JWTSecret)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate tokens", err)
			return
		}

		// Save refresh token
		err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.Cookie.RefreshTokenTTL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", err)
			return
		}

		// Set access token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     h.Auth.Config.Cookie.CookieName,
			Value:    accessToken,
			Expires:  time.Now().Add(h.Auth.Config.Cookie.AccessTokenTTL),
			Domain:   h.Auth.Config.Cookie.CookieDomain,
			Path:     h.Auth.Config.Cookie.CookiePath,
			Secure:   h.Auth.Config.Cookie.CookieSecure,
			HttpOnly: h.Auth.Config.Cookie.HttpOnly,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
		})

		response = map[string]interface{}{
			"message":       "Email verified successfully",
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		}
	} else {
		response = map[string]interface{}{
			"message": "Email verified successfully",
		}
	}

	// json.NewEncoder(w).Encode(response)
	err = utils.RespondWithJSON(w, http.StatusOK, response)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", err)
		return
	}
}

// HandleResendVerificationEmail resends verification email
func (h *AuthHandler) HandleResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	if !h.Auth.Config.EnableEmailVerification {
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
	verificationToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate verification token", err)
		return
	}

	// Save verification token (valid for 24 hours)
	err = h.Auth.Repository.GetTokenRepository().SaveEmailVerificationToken(user.ID, verificationToken, 24*time.Hour)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification token", err)
		return
	}

	// Send verification email
	if h.Auth.Config.EmailSender != nil {
		verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
			h.Auth.Config.EmailVerificationURL,
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

// sendTwoFactorCode sends a two-factor verification code
func (h *AuthHandler) sendTwoFactorCode(user *models.User) error {
	// Generate random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Save code (valid for 10 minutes)
	err := h.Auth.Repository.GetTokenRepository().SaveTwoFactorCode(user.ID, code, 10*time.Minute)
	if err != nil {
		return err
	}

	// Send code via configured method
	if h.Auth.Config.TwoFactorMethod == "email" && h.Auth.Config.EmailSender != nil {
		return h.Auth.Config.EmailSender.SendTwoFactorCode(*user, code)
	} else if h.Auth.Config.TwoFactorMethod == "sms" && h.Auth.Config.SMSSender != nil {
		// Assuming user has a phone number
		return h.Auth.Config.SMSSender.SendTwoFactorCode(*user, code)
	}

	return errors.New("no valid two-factor delivery method configured")
}
