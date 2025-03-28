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
)

// HandleForgotPassword handles password reset requests
func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user exists
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		// Don't reveal if email exists
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If your email address exists in our database, you will receive a password recovery link at your email address shortly.",
		})
		return
	}

	// Generate reset token
	resetToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		http.Error(w, "Failed to generate reset token", http.StatusInternalServerError)
		return
	}
	// Save reset token
	err = h.Auth.Repository.GetTokenRepository().SavePasswordResetToken(user.ID, resetToken, 1*time.Hour)
	if err != nil {
		http.Error(w, "Failed to save reset token", http.StatusInternalServerError)
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
			fmt.Printf("Failed to send password reset email: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If your email address exists in our database, you will receive a password recovery link at your email address shortly.",
	})
}

// HandleResetPassword handles password reset
func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate token
	valid, userID, err := h.Auth.Repository.GetTokenRepository().ValidatePasswordResetToken(req.Token)
	if err != nil || !valid {
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	// Validate password against policy
	if err := validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword, h.Auth.Config.PasswordPolicy.HashSaltLength)
	if err != nil {
		http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update password
	user.Password = hashedPassword
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Invalidate token
	h.Auth.Repository.GetTokenRepository().InvalidatePasswordResetToken(req.Token)

	// Invalidate all refresh tokens for security
	h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password has been reset successfully.",
	})
}

// HandleUpdateUser handles user profile updates
func (h *AuthHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req schemas.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get current user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}

	// Handle password change if provided
	// if req.CurrentPassword != "" && req.NewPassword != "" {
	// 	// Verify current password
	// 	err = utils.ValidatePassword(user.Password, req.CurrentPassword)
	// 	if err != nil {
	// 		http.Error(w, "Current password is incorrect", http.StatusBadRequest)
	// 		return
	// 	}

	// 	// Validate new password against policy
	// 	if err := validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
	// 		http.Error(w, err.Error(), http.StatusBadRequest)
	// 		return
	// 	}

	// 	// Hash new password
	// 	hashedPassword, err := utils.HashPassword(req.NewPassword)
	// 	if err != nil {
	// 		http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}
	// 	user.Password = hashedPassword

	// 	// Invalidate all refresh tokens for security
	// 	h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)
	// }

	// Update user
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    userResponse,
		"message": "User updated successfully",
	})
}

// HandleDeactivateUser handles user account deactivation
func (h *AuthHandler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req schemas.DeactivateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get current user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Verify password
	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, "Password is incorrect", http.StatusBadRequest)
		return
	}

	// Deactivate user
	user.Active = false
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to deactivate account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Invalidate all refresh tokens
	h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Account deactivated successfully",
	})
}

// HandleEnableTwoFactor handles enabling two-factor authentication
func (h *AuthHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.Auth.Config.EnableTwoFactor {
		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Send two-factor code
	err = sendTwoFactorCode(h, user)
	if err != nil {
		http.Error(w, "Failed to send two-factor code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":           "Two-factor verification code sent",
		"two_factor_method": h.Auth.Config.TwoFactorMethod,
	})
}

// HandleVerifyTwoFactor verifies two-factor code and enables 2FA
func (h *AuthHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.Auth.Config.EnableTwoFactor {
		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req schemas.VerifyTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Validate two-factor code
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTwoFactorCode(user.ID, req.Code)
	if err != nil || !valid {
		http.Error(w, "Invalid two-factor code", http.StatusBadRequest)
		return
	}

	// Enable two-factor authentication
	user.TwoFactorEnabled = true
	user.TwoFactorVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to enable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Two-factor authentication enabled successfully",
	})
}

// HandleDisableTwoFactor disables two-factor authentication
func (h *AuthHandler) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.Cookie.CookieName, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req schemas.DisableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Verify password
	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, "Password is incorrect", http.StatusBadRequest)
		return
	}

	// Disable two-factor authentication
	user.TwoFactorEnabled = false
	user.TwoFactorVerified = false
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to disable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Two-factor authentication disabled successfully",
	})
}

// HandleVerifyEmail verifies user's email
func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var token, email string
	if r.Method == http.MethodGet {
		token = r.URL.Query().Get("token")
		email = r.URL.Query().Get("email")
	} else {
		var req schemas.VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		token = req.Token
		email = req.Email
	}

	if token == "" || email == "" {
		http.Error(w, "Missing token or email", http.StatusBadRequest)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Validate verification token
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateEmailVerificationToken(user.ID, token)
	if err != nil || !valid {
		http.Error(w, "Invalid or expired verification token", http.StatusBadRequest)
		return
	}

	// Mark email as verified
	user.EmailVerified = true
	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
	if err != nil {
		http.Error(w, "Failed to verify email: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Invalidate verification token
	h.Auth.Repository.GetTokenRepository().InvalidateEmailVerificationToken(user.ID, token)

	// Generate tokens if needed
	var response map[string]interface{}
	if r.Method == http.MethodPost {
		accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.Cookie.AccessTokenTTL,h.Auth.Config.Cookie.RefreshTokenTTL, h.Auth.Config.JWTSecret)
		if err != nil {
			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
			return
		}

		// Save refresh token
		err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.Cookie.RefreshTokenTTL)
		if err != nil {
			http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleResendVerificationEmail resends verification email
func (h *AuthHandler) HandleResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.Auth.Config.EnableEmailVerification {
		http.Error(w, "Email verification is not enabled", http.StatusBadRequest)
		return
	}

	var req schemas.ResendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		// Don't reveal if email exists for security
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If your email address exists in our database, you will receive a verification email shortly.",
		})
		return
	}

	// Check if already verified
	if user.EmailVerified {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Email already verified.",
		})
		return
	}

	// Generate verification token
	verificationToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
		return
	}

	// Save verification token (valid for 24 hours)
	err = h.Auth.Repository.GetTokenRepository().SaveEmailVerificationToken(user.ID, verificationToken, 24*time.Hour)
	if err != nil {
		http.Error(w, "Failed to save verification token", http.StatusInternalServerError)
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
			// Log error but don't reveal to client
			fmt.Printf("Failed to send verification email: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If your email address exists in our database, you will receive a verification email shortly.",
	})
}

// sendTwoFactorCode sends a two-factor verification code
func sendTwoFactorCode(h *AuthHandler, user *models.User) error {
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
