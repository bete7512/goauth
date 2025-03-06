package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/types"
	"github.com/bete7512/goauth/utils"
)

type AuthHandler struct {
	Auth *types.Auth
}

func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Execute before hooks
		if h.Auth.HookManager != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
				return
			}
		}
		handler(w, r)
		// Execute after hooks
		if h.Auth.HookManager != nil {
			h.Auth.HookManager.ExecuteAfterHooks(route, w, r)
		}
	}
}

// HandleRegister handles user registration
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate password against policy
	if err := validatePasswordPolicy(req.Password, h.Auth.Config.PasswordPolicy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if email already exists
	existingUser, _ := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if existingUser != nil {
		http.Error(w, "Email already in use", http.StatusConflict)
		return
	}

	// Create user object
	user := models.User{
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		Email:            req.Email,
		EmailVerified:    !h.Auth.Config.EnableEmailVerification,
		Active:           true,
		TwoFactorEnabled: false,
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = hashedPassword

	// Create user in database
	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
	if err != nil {
		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle email verification if enabled
	if h.Auth.Config.EnableEmailVerification {
		verificationToken, err := utils.GenerateRandomToken(32)
		if err != nil {
			http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
			return
		}

		// Save verification token
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

			err = h.Auth.Config.EmailSender.SendVerification(user.Email, user.FirstName, verificationURL)
			if err != nil {
				// Log error but continue - user can request verification email later
				fmt.Printf("Failed to send verification email: %v\n", err)
			}
		}
	}

	// Generate tokens
	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
		return
	}

	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.CookieName,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
		Domain:   h.Auth.Config.CookieDomain,
		Path:     h.Auth.Config.CookiePath,
		Secure:   h.Auth.Config.CookieSecure,
		HttpOnly: h.Auth.Config.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   h.Auth.Config.MaxCookieAge,
	})

	// Prepare response
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	response := map[string]interface{}{
		"user":          userResponse,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"verified":      user.EmailVerified,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleLogin handles user login
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Check if user is active
	if !user.Active {
		http.Error(w, "Account is deactivated", http.StatusUnauthorized)
		return
	}

	// Check if email verification is required
	if h.Auth.Config.EnableEmailVerification && !user.EmailVerified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		return
	}

	// Validate password
	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Handle two-factor authentication if enabled
	if h.Auth.Config.EnableTwoFactor && user.TwoFactorEnabled {
		if req.TwoFactorCode == "" {
			// First stage login - send 2FA code and expect a second request
			err = sendTwoFactorCode(h, user)
			if err != nil {
				http.Error(w, "Failed to send two-factor code", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":           "Two-factor code sent",
				"requires_2fa":      true,
				"two_factor_method": h.Auth.Config.TwoFactorMethod,
			})
			return
		} else {
			// Validate two-factor code
			valid, err := h.Auth.Repository.GetTokenRepository().ValidateTwoFactorCode(user.ID, req.TwoFactorCode)
			if err != nil || !valid {
				http.Error(w, "Invalid two-factor code", http.StatusUnauthorized)
				return
			}
		}
	}

	// Generate tokens
	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
		return
	}

	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.CookieName,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
		Domain:   h.Auth.Config.CookieDomain,
		Path:     h.Auth.Config.CookiePath,
		Secure:   h.Auth.Config.CookieSecure,
		HttpOnly: h.Auth.Config.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   h.Auth.Config.MaxCookieAge,
	})

	// Prepare user response that doesn't include sensitive data
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	// Send response
	response := map[string]interface{}{
		"user":          userResponse,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from cookie or Authorization header
	token := extractToken(r, h.Auth.Config.CookieName)
	if token == "" {
		http.Error(w, "No authentication token provided", http.StatusBadRequest)
		return
	}

	// Validate token
	claims, err := utils.ValidateToken(token, h.Auth.Config.JWTSecret)
	if err == nil {
		// If token is valid, invalidate all refresh tokens for the user
		userID := claims["user_id"].(string)
		h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.CookieDomain,
		Path:     h.Auth.Config.CookiePath,
		Secure:   h.Auth.Config.CookieSecure,
		HttpOnly: h.Auth.Config.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully logged out",
	})
}

// HandleRefreshToken handles token refresh
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate refresh token
	claims, err := utils.ValidateToken(req.RefreshToken, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		http.Error(w, "Invalid refresh token claims", http.StatusUnauthorized)
		return
	}

	// Check if token is valid in the repository
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateRefreshToken(userID, req.RefreshToken)
	if err != nil || !valid {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Check if user is active
	if !user.Active {
		http.Error(w, "Account is deactivated", http.StatusUnauthorized)
		return
	}

	// Generate new tokens
	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Invalidate old refresh token
	h.Auth.Repository.GetTokenRepository().InvalidateRefreshToken(userID, req.RefreshToken)

	// Save new refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.CookieName,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
		Domain:   h.Auth.Config.CookieDomain,
		Path:     h.Auth.Config.CookiePath,
		Secure:   h.Auth.Config.CookieSecure,
		HttpOnly: h.Auth.Config.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   h.Auth.Config.MaxCookieAge,
	})

	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleGetUser returns the current user's profile
func (h *AuthHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate user
	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
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
	json.NewEncoder(w).Encode(userResponse)
}

// Helper functions

// validatePasswordPolicy validates a password against the configured policy
func validatePasswordPolicy(password string, policy types.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if policy.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if policy.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// authenticateRequest extracts and validates the token from a request
func authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
	token := extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := utils.ValidateToken(token, jwtSecret)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

// extractToken extracts the JWT token from the request
func extractToken(r *http.Request, cookieName string) string {
	// Try to get from cookie first
	if cookieName != "" {
		cookie, err := r.Cookie(cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	// Try to get from Authorization header
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}

	return ""
}

// package handlers

// import (
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"math/rand"
// 	"net/http"
// 	"strings"
// 	"time"
// 	"unicode"

// 	"github.com/bete7512/goauth/models"
// 	"github.com/bete7512/goauth/schemas"
// 	"github.com/bete7512/goauth/types"
// 	"github.com/bete7512/goauth/utils"
// )

// type AuthHandler struct {
// 	Auth *types.Auth
// }

// func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Execute before hooks
// 		if h.Auth.HookManager != nil {
// 			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
// 				return
// 			}
// 		}
// 		handler(w, r)
// 		// Execute after hooks
// 		if h.Auth.HookManager != nil {
// 			h.Auth.HookManager.ExecuteAfterHooks(route, w, r)
// 		}
// 	}
// }
// // HandleRegister handles user registration
// func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.RegisterRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Validate password against policy
// 	if err := validatePasswordPolicy(req.Password, h.Auth.Config.PasswordPolicy); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Check if email already exists
// 	existingUser, _ := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// 	if existingUser != nil {
// 		http.Error(w, "Email already in use", http.StatusConflict)
// 		return
// 	}

// 	// Create user object
// 	user := models.User{
// 		FirstName:        req.FirstName,
// 		LastName:         req.LastName,
// 		Email:            req.Email,
// 		EmailVerified:    !h.Auth.Config.EnableEmailVerification,
// 		Active:           true,
// 		TwoFactorEnabled: false,
// 	}

// 	// Hash password
// 	hashedPassword, err := utils.HashPassword(req.Password)
// 	if err != nil {
// 		http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	user.Password = hashedPassword

// 	// // Trigger pre-registration hook if defined
// 	// if h.Auth.HookManager != nil {
// 	// 	if err := h.Auth.HookManager.ExecuteAfterHooks("register", w, r); err != nil {
// 	// 		http.Error(w, "Registration rejected: "+err.Error(), http.StatusBadRequest)
// 	// 		return
// 	// 	}
// 	// }

// 	// Create user in database
// 	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
// 	if err != nil {
// 		http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Handle email verification if enabled
// 	if h.Auth.Config.EnableEmailVerification {
// 		verificationToken, err := utils.GenerateRandomToken(32)
// 		if err != nil {
// 			http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
// 			return
// 		}

// 		// Save verification token
// 		err = h.Auth.Repository.GetTokenRepository().SaveEmailVerificationToken(user.ID, verificationToken, 24*time.Hour)
// 		if err != nil {
// 			http.Error(w, "Failed to save verification token", http.StatusInternalServerError)
// 			return
// 		}

// 		// Send verification email
// 		if h.Auth.Config.EmailSender != nil {
// 			verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
// 				h.Auth.Config.EmailVerificationURL,
// 				verificationToken,
// 				user.Email)

// 			err = h.Auth.Config.EmailSender.SendVerification(user.Email, user.FirstName, verificationURL)
// 			if err != nil {
// 				// Log error but continue - user can request verification email later
// 				fmt.Printf("Failed to send verification email: %v\n", err)
// 			}
// 		}
// 	}

// 	// Generate tokens
// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
// 		return
// 	}

// 	// Save refresh token
// 	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
// 	if err != nil {
// 		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Set access token cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     h.Auth.Config.CookieName,
// 		Value:    accessToken,
// 		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
// 		Domain:   h.Auth.Config.CookieDomain,
// 		Path:     h.Auth.Config.CookiePath,
// 		Secure:   h.Auth.Config.CookieSecure,
// 		HttpOnly: h.Auth.Config.HttpOnly,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   h.Auth.Config.MaxCookieAge,
// 	})

// 	// Execute post-registration hook if defined
// 	// if h.Auth.HookManager != nil {
// 	// 	h.Auth.HookManager.ExecutePostRegistration(&user)
// 	// }

// 	// Prepare response
// 	userResponse := schemas.UserResponse{
// 		ID:        user.ID,
// 		FirstName: user.FirstName,
// 		LastName:  user.LastName,
// 		Email:     user.Email,
// 		CreatedAt: user.CreatedAt,
// 	}

// 	response := map[string]interface{}{
// 		"user":          userResponse,
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 		"verified":      user.EmailVerified,
// 	}

// 	// Send response
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusCreated)
// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

// // HandleLogin handles user login
// func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.LoginRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// // Execute pre-login hook if defined
// 	// if h.Auth.HookManager != nil {
// 	// 	if err := h.Auth.HookManager.ExecutePreLogin(&req); err != nil {
// 	// 		http.Error(w, "Login rejected: "+err.Error(), http.StatusUnauthorized)
// 	// 		return
// 	// 	}
// 	// }

// 	// Get user by email
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// 	if err != nil {
// 		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
// 		return
// 	}

// 	// Check if user is active
// 	if !user.Active {
// 		http.Error(w, "Account is deactivated", http.StatusUnauthorized)
// 		return
// 	}

// 	// Check if email verification is required
// 	if h.Auth.Config.EnableEmailVerification && !user.EmailVerified {
// 		http.Error(w, "Email not verified", http.StatusUnauthorized)
// 		return
// 	}

// 	// Validate password
// 	err = utils.ValidatePassword(user.Password, req.Password)
// 	if err != nil {
// 		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
// 		return
// 	}

// 	// Handle two-factor authentication if enabled
// 	if h.Auth.Config.EnableTwoFactor && user.TwoFactorEnabled {
// 		if req.TwoFactorCode == "" {
// 			// First stage login - send 2FA code and expect a second request
// 			err = sendTwoFactorCode(h, user)
// 			if err != nil {
// 				http.Error(w, "Failed to send two-factor code", http.StatusInternalServerError)
// 				return
// 			}

// 			w.Header().Set("Content-Type", "application/json")
// 			w.WriteHeader(http.StatusOK)
// 			json.NewEncoder(w).Encode(map[string]interface{}{
// 				"message":           "Two-factor code sent",
// 				"requires_2fa":      true,
// 				"two_factor_method": h.Auth.Config.TwoFactorMethod,
// 			})
// 			return
// 		} else {
// 			// Validate two-factor code
// 			valid, err := h.Auth.Repository.GetTokenRepository().ValidateTwoFactorCode(user.ID, req.TwoFactorCode)
// 			if err != nil || !valid {
// 				http.Error(w, "Invalid two-factor code", http.StatusUnauthorized)
// 				return
// 			}
// 		}
// 	}

// 	// Generate tokens
// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
// 		return
// 	}

// 	// Save refresh token
// 	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
// 	if err != nil {
// 		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Set access token cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     h.Auth.Config.CookieName,
// 		Value:    accessToken,
// 		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
// 		Domain:   h.Auth.Config.CookieDomain,
// 		Path:     h.Auth.Config.CookiePath,
// 		Secure:   h.Auth.Config.CookieSecure,
// 		HttpOnly: h.Auth.Config.HttpOnly,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   h.Auth.Config.MaxCookieAge,
// 	})

// 	// // Execute post-login hook if defined
// 	// if h.Auth.HookManager != nil {
// 	// 	h.Auth.HookManager.ExecutePostLogin(user)
// 	// }

// 	// Prepare user response that doesn't include sensitive data
// 	userResponse := schemas.UserResponse{
// 		ID:        user.ID,
// 		FirstName: user.FirstName,
// 		LastName:  user.LastName,
// 		Email:     user.Email,
// 		CreatedAt: user.CreatedAt,
// 	}

// 	// Send response
// 	response := map[string]interface{}{
// 		"user":          userResponse,
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

// // HandleLogout handles user logout
// func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Get token from cookie or Authorization header
// 	token := extractToken(r, h.Auth.Config.CookieName)
// 	if token == "" {
// 		http.Error(w, "No authentication token provided", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate token
// 	claims, err := utils.ValidateToken(token, h.Auth.Config.JWTSecret)
// 	if err == nil {
// 		// If token is valid, invalidate all refresh tokens for the user
// 		userID := claims["user_id"].(string)
// 		h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)

// 		// // Execute post-logout hook if defined
// 		// if h.Auth.HookManager != nil {
// 		// 	h.Auth.HookManager.ExecutePostLogout(userID)
// 		// }
// 	}

// 	// Clear cookie regardless of token validity
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     h.Auth.Config.CookieName,
// 		Value:    "",
// 		Expires:  time.Unix(0, 0),
// 		Domain:   h.Auth.Config.CookieDomain,
// 		Path:     h.Auth.Config.CookiePath,
// 		Secure:   h.Auth.Config.CookieSecure,
// 		HttpOnly: h.Auth.Config.HttpOnly,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   -1,
// 	})

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "Successfully logged out",
// 	})
// }

// // HandleRefreshToken handles token refresh
// func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.RefreshTokenRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Validate refresh token
// 	claims, err := utils.ValidateToken(req.RefreshToken, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
// 		return
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		http.Error(w, "Invalid refresh token claims", http.StatusUnauthorized)
// 		return
// 	}

// 	// Check if token is valid in the repository
// 	valid, err := h.Auth.Repository.GetTokenRepository().ValidateRefreshToken(userID, req.RefreshToken)
// 	if err != nil || !valid {
// 		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusUnauthorized)
// 		return
// 	}

// 	// Check if user is active
// 	if !user.Active {
// 		http.Error(w, "Account is deactivated", http.StatusUnauthorized)
// 		return
// 	}

// 	// Generate new tokens
// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
// 		return
// 	}

// 	// Invalidate old refresh token
// 	h.Auth.Repository.GetTokenRepository().InvalidateRefreshToken(userID, req.RefreshToken)

// 	// Save new refresh token
// 	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
// 	if err != nil {
// 		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Set access token cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     h.Auth.Config.CookieName,
// 		Value:    accessToken,
// 		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
// 		Domain:   h.Auth.Config.CookieDomain,
// 		Path:     h.Auth.Config.CookiePath,
// 		Secure:   h.Auth.Config.CookieSecure,
// 		HttpOnly: h.Auth.Config.HttpOnly,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   h.Auth.Config.MaxCookieAge,
// 	})

// 	response := map[string]interface{}{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

// // HandleForgotPassword handles password reset requests
// func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.ForgotPasswordRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Check if user exists
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// 	if err != nil {
// 		// Don't reveal if email exists
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusOK)
// 		json.NewEncoder(w).Encode(map[string]string{
// 			"message": "If your email address exists in our database, you will receive a password recovery link at your email address shortly.",
// 		})
// 		return
// 	}

// 	// Generate reset token
// 	resetToken, err := utils.GenerateRandomToken(32)
// 	if err != nil {
// 		http.Error(w, "Failed to generate reset token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Save reset token (valid for 1 hour)
// 	err = h.Auth.Repository.GetTokenRepository().SavePasswordResetToken(user.ID, resetToken, 1*time.Hour)
// 	if err != nil {
// 		http.Error(w, "Failed to save reset token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Send reset email
// 	if h.Auth.Config.EmailSender != nil {
// 		resetURL := fmt.Sprintf("%s?token=%s&email=%s",
// 			h.Auth.Config.PasswordResetURL,
// 			resetToken,
// 			user.Email)

// 		err = h.Auth.Config.EmailSender.SendPasswordReset(user.Email, user.FirstName, resetURL)
// 		if err != nil {
// 			// Log error but don't reveal to client
// 			fmt.Printf("Failed to send password reset email: %v\n", err)
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "If your email address exists in our database, you will receive a password recovery link at your email address shortly.",
// 	})
// }

// // HandleResetPassword handles password reset
// func (h *AuthHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.ResetPasswordRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Validate token
// 	valid, userID, err := h.Auth.Repository.GetTokenRepository().ValidatePasswordResetToken(req.Token)
// 	if err != nil || !valid {
// 		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate password against policy
// 	if err := validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Hash new password
// 	hashedPassword, err := utils.HashPassword(req.NewPassword)
// 	if err != nil {
// 		http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Update password
// 	user.Password = hashedPassword
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Invalidate token
// 	h.Auth.Repository.GetTokenRepository().InvalidatePasswordResetToken(req.Token)

// 	// Invalidate all refresh tokens for security
// 	h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "Password has been reset successfully.",
// 	})
// }

// // HandleUpdateUser handles user profile updates
// func (h *AuthHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	var req schemas.UpdateUserRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get current user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Update fields
// 	if req.FirstName != "" {
// 		user.FirstName = req.FirstName
// 	}
// 	if req.LastName != "" {
// 		user.LastName = req.LastName
// 	}

// 	// Handle password change if provided
// 	if req.CurrentPassword != "" && req.NewPassword != "" {
// 		// Verify current password
// 		err = utils.ValidatePassword(user.Password, req.CurrentPassword)
// 		if err != nil {
// 			http.Error(w, "Current password is incorrect", http.StatusBadRequest)
// 			return
// 		}

// 		// Validate new password against policy
// 		if err := validatePasswordPolicy(req.NewPassword, h.Auth.Config.PasswordPolicy); err != nil {
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		// Hash new password
// 		hashedPassword, err := utils.HashPassword(req.NewPassword)
// 		if err != nil {
// 			http.Error(w, "Failed to secure password: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		user.Password = hashedPassword

// 		// Invalidate all refresh tokens for security
// 		h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)
// 	}

// 	// Update user
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Prepare user response
// 	userResponse := schemas.UserResponse{
// 		ID:        user.ID,
// 		FirstName: user.FirstName,
// 		LastName:  user.LastName,
// 		Email:     user.Email,
// 		CreatedAt: user.CreatedAt,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"user":    userResponse,
// 		"message": "User updated successfully",
// 	})
// }

// // HandleDeactivateUser handles user account deactivation
// func (h *AuthHandler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	var req schemas.DeactivateUserRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get current user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Verify password
// 	err = utils.ValidatePassword(user.Password, req.Password)
// 	if err != nil {
// 		http.Error(w, "Password is incorrect", http.StatusBadRequest)
// 		return
// 	}

// 	// Deactivate user
// 	user.Active = false
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to deactivate account: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Invalidate all refresh tokens
// 	h.Auth.Repository.GetTokenRepository().InvalidateAllRefreshTokens(userID)

// 	// Clear cookie
// 	http.SetCookie(w, &http.Cookie{
// 		Name:     h.Auth.Config.CookieName,
// 		Value:    "",
// 		Expires:  time.Unix(0, 0),
// 		Domain:   h.Auth.Config.CookieDomain,
// 		Path:     h.Auth.Config.CookiePath,
// 		Secure:   h.Auth.Config.CookieSecure,
// 		HttpOnly: h.Auth.Config.HttpOnly,
// 		SameSite: http.SameSiteStrictMode,
// 		MaxAge:   -1,
// 	})

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "Account deactivated successfully",
// 	})
// }

// // HandleGetUser returns the current user's profile
// func (h *AuthHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Prepare user response
// 	userResponse := schemas.UserResponse{
// 		ID:        user.ID,
// 		FirstName: user.FirstName,
// 		LastName:  user.LastName,
// 		Email:     user.Email,
// 		CreatedAt: user.CreatedAt,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(userResponse)
// }

// // HandleEnableTwoFactor handles enabling two-factor authentication
// func (h *AuthHandler) HandleEnableTwoFactor(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	if !h.Auth.Config.EnableTwoFactor {
// 		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Send two-factor code
// 	err = sendTwoFactorCode(h, user)
// 	if err != nil {
// 		http.Error(w, "Failed to send two-factor code: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message":           "Two-factor verification code sent",
// 		"two_factor_method": h.Auth.Config.TwoFactorMethod,
// 	})
// }

// // HandleVerifyTwoFactor verifies two-factor code and enables 2FA
// func (h *AuthHandler) HandleVerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	if !h.Auth.Config.EnableTwoFactor {
// 		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	var req schemas.VerifyTwoFactorRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate two-factor code
// 	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTwoFactorCode(user.ID, req.Code)
// 	if err != nil || !valid {
// 		http.Error(w, "Invalid two-factor code", http.StatusBadRequest)
// 		return
// 	}

// 	// Enable two-factor authentication
// 	user.TwoFactorEnabled = true
// 	user.TwoFactorVerified = true
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to enable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message": "Two-factor authentication enabled successfully",
// 	})
// }

// // HandleDisableTwoFactor disables two-factor authentication
// func (h *AuthHandler) HandleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Authenticate user
// 	userID, err := authenticateRequest(r, h.Auth.Config.CookieName, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	var req schemas.DisableTwoFactorRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get user
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Verify password
// 	err = utils.ValidatePassword(user.Password, req.Password)
// 	if err != nil {
// 		http.Error(w, "Password is incorrect", http.StatusBadRequest)
// 		return
// 	}

// 	// Disable two-factor authentication
// 	user.TwoFactorEnabled = false
// 	user.TwoFactorVerified = false
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to disable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"message": "Two-factor authentication disabled successfully",
// 	})
// }

// // HandleVerifyEmail verifies user's email
// func (h *AuthHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodGet && r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Extract token and email from query parameters or request body
// 	var token, email string
// 	if r.Method == http.MethodGet {
// 		token = r.URL.Query().Get("token")
// 		email = r.URL.Query().Get("email")
// 	} else {
// 		var req schemas.VerifyEmailRequest
// 		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		token = req.Token
// 		email = req.Email
// 	}

// 	if token == "" || email == "" {
// 		http.Error(w, "Missing token or email", http.StatusBadRequest)
// 		return
// 	}

// 	// Get user by email
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(email)
// 	if err != nil {
// 		http.Error(w, "User not found", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate verification token
// 	valid, err := h.Auth.Repository.GetTokenRepository().ValidateEmailVerificationToken(user.ID, token)
// 	if err != nil || !valid {
// 		http.Error(w, "Invalid or expired verification token", http.StatusBadRequest)
// 		return
// 	}

// 	// Mark email as verified
// 	user.EmailVerified = true
// 	err = h.Auth.Repository.GetUserRepository().UpdateUser(user)
// 	if err != nil {
// 		http.Error(w, "Failed to verify email: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// Invalidate verification token
// 	h.Auth.Repository.GetTokenRepository().InvalidateEmailVerificationToken(user.ID, token)

// 	// Generate tokens if needed
// 	var response map[string]interface{}
// 	if r.Method == http.MethodPost {
// 		accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 		if err != nil {
// 			http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
// 			return
// 		}

// 		// Save refresh token
// 		err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.RefreshTokenTTL)
// 		if err != nil {
// 			http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
// 			return
// 		}

// 		// Set access token cookie
// 		http.SetCookie(w, &http.Cookie{
// 			Name:     h.Auth.Config.CookieName,
// 			Value:    accessToken,
// 			Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
// 			Domain:   h.Auth.Config.CookieDomain,
// 			Path:     h.Auth.Config.CookiePath,
// 			Secure:   h.Auth.Config.CookieSecure,
// 			HttpOnly: h.Auth.Config.HttpOnly,
// 			SameSite: http.SameSiteStrictMode,
// 			MaxAge:   h.Auth.Config.MaxCookieAge,
// 		})

// 		response = map[string]interface{}{
// 			"message":       "Email verified successfully",
// 			"access_token":  accessToken,
// 			"refresh_token": refreshToken,
// 		}
// 	} else {
// 		response = map[string]interface{}{
// 			"message": "Email verified successfully",
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(response)
// }

// // HandleResendVerificationEmail resends verification email
// func (h *AuthHandler) HandleResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	if !h.Auth.Config.EnableEmailVerification {
// 		http.Error(w, "Email verification is not enabled", http.StatusBadRequest)
// 		return
// 	}

// 	var req schemas.ResendVerificationEmailRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Get user by email
// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// 	if err != nil {
// 		// Don't reveal if email exists for security
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusOK)
// 		json.NewEncoder(w).Encode(map[string]string{
// 			"message": "If your email address exists in our database, you will receive a verification email shortly.",
// 		})
// 		return
// 	}

// 	// Check if already verified
// 	if user.EmailVerified {
// 		w.Header().Set("Content-Type", "application/json")
// 		w.WriteHeader(http.StatusOK)
// 		json.NewEncoder(w).Encode(map[string]string{
// 			"message": "Email already verified.",
// 		})
// 		return
// 	}

// 	// Generate verification token
// 	verificationToken, err := utils.GenerateRandomToken(32)
// 	if err != nil {
// 		http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Save verification token (valid for 24 hours)
// 	err = h.Auth.Repository.GetTokenRepository().SaveEmailVerificationToken(user.ID, verificationToken, 24*time.Hour)
// 	if err != nil {
// 		http.Error(w, "Failed to save verification token", http.StatusInternalServerError)
// 		return
// 	}

// 	// Send verification email
// 	if h.Auth.Config.EmailSender != nil {
// 		verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
// 			h.Auth.Config.EmailVerificationURL,
// 			verificationToken,
// 			user.Email)

// 		err = h.Auth.Config.EmailSender.SendVerification(user.Email, user.FirstName, verificationURL)
// 		if err != nil {
// 			// Log error but don't reveal to client
// 			fmt.Printf("Failed to send verification email: %v\n", err)
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{
// 		"message": "If your email address exists in our database, you will receive a verification email shortly.",
// 	})
// }

// // Helper functions

// // validatePasswordPolicy validates a password against the configured policy
// func validatePasswordPolicy(password string, policy types.PasswordPolicy) error {
// 	if len(password) < policy.MinLength {
// 		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
// 	}

// 	var hasUpper, hasLower, hasNumber, hasSpecial bool
// 	for _, char := range password {
// 		switch {
// 		case unicode.IsUpper(char):
// 			hasUpper = true
// 		case unicode.IsLower(char):
// 			hasLower = true
// 		case unicode.IsNumber(char):
// 			hasNumber = true
// 		case unicode.IsPunct(char) || unicode.IsSymbol(char):
// 			hasSpecial = true
// 		}
// 	}

// 	if policy.RequireUpper && !hasUpper {
// 		return errors.New("password must contain at least one uppercase letter")
// 	}
// 	if policy.RequireLower && !hasLower {
// 		return errors.New("password must contain at least one lowercase letter")
// 	}
// 	if policy.RequireNumber && !hasNumber {
// 		return errors.New("password must contain at least one number")
// 	}
// 	if policy.RequireSpecial && !hasSpecial {
// 		return errors.New("password must contain at least one special character")
// 	}

// 	return nil
// }

// // authenticateRequest extracts and validates the token from a request
// func authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
// 	token := extractToken(r, cookieName)
// 	if token == "" {
// 		return "", errors.New("no authentication token provided")
// 	}

// 	claims, err := utils.ValidateToken(token, jwtSecret)
// 	if err != nil {
// 		return "", err
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		return "", errors.New("invalid token claims")
// 	}

// 	return userID, nil
// }

// // extractToken extracts the JWT token from the request
// func extractToken(r *http.Request, cookieName string) string {
// 	// Try to get from cookie first
// 	if cookieName != "" {
// 		cookie, err := r.Cookie(cookieName)
// 		if err == nil && cookie.Value != "" {
// 			return cookie.Value
// 		}
// 	}

// 	// Try to get from Authorization header
// 	bearerToken := r.Header.Get("Authorization")
// 	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
// 		return bearerToken[7:]
// 	}

// 	return ""
// }

// // sendTwoFactorCode sends a two-factor verification code
// func sendTwoFactorCode(h *AuthHandler, user *models.User) error {
// 	// Generate random 6-digit code
// 	code := fmt.Sprintf("%06d", rand.Intn(1000000))

// 	// Save code (valid for 10 minutes)
// 	err := h.Auth.Repository.GetTokenRepository().SaveTwoFactorCode(user.ID, code, 10*time.Minute)
// 	if err != nil {
// 		return err
// 	}

// 	// Send code via configured method
// 	if h.Auth.Config.TwoFactorMethod == "email" && h.Auth.Config.EmailSender != nil {
// 		return h.Auth.Config.EmailSender.SendTwoFactorCode(user.Email, user.FirstName, code)
// 	} else if h.Auth.Config.TwoFactorMethod == "sms" && h.Auth.Config.SMSSender != nil {
// 		// Assuming user has a phone number
// 		return h.Auth.Config.SMSSender.SendTwoFactorCode(user.PhoneNumber, user.FirstName, code)
// 	}

// 	return errors.New("no valid two-factor delivery method configured")
// }

// // // auth/routes/handlers/auth_handler.go
// // package handlers

// // import (
// // 	"encoding/json"
// // 	"net/http"
// // 	"time"

// // 	"github.com/bete7512/goauth/models"
// // 	"github.com/bete7512/goauth/schemas"
// // 	"github.com/bete7512/goauth/types"
// // 	"github.com/bete7512/goauth/utils"
// // )

// // type AuthHandler struct {
// // 	Auth *types.Auth
// // }

// // func New(config *types.Auth) *AuthHandler {
// // 	return &AuthHandler{Auth: config}
// // }

// // // WithHooks wraps a handler function with before and after hooks
// // func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
// // 	return func(w http.ResponseWriter, r *http.Request) {
// // 		// Execute before hooks
// // 		if h.Auth.HookManager != nil {
// // 			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
// // 				return
// // 			}
// // 		}
// // 		handler(w, r)
// // 		// Execute after hooks
// // 		if h.Auth.HookManager != nil {
// // 			h.Auth.HookManager.ExecuteAfterHooks(route, w, r)
// // 		}
// // 	}
// // }

// // func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
// // 	if r.Method != http.MethodPost {
// // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // 		return
// // 	}

// // 	var req schemas.RegisterRequest
// // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}

// // 	user := models.User{
// // 		FirstName: req.FirstName,
// // 		LastName:  req.LastName,
// // 		Email:     req.Email,
// // 	}
// // 	hashedPassword, err := utils.HashPassword(req.Password)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}
// // 	user.Password = hashedPassword
// // 	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}

// // 	if h.Auth.Config.EnableEmailVerification{
// // 		// Send verification email
// // 	}

// // 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // 		return
// // 	}

// // 	response := map[string]interface{}{
// // 		"user":          user,
// // 		"access_token":  accessToken,
// // 		"refresh_token": refreshToken,
// // 	}

// // 	w.Header().Set("Content-Type", "application/json")
// // 	w.WriteHeader(http.StatusCreated)
// // 	if err := json.NewEncoder(w).Encode(response); err != nil {
// // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // 		return
// // 	}
// // }

// // func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
// // 	if r.Method != http.MethodPost {
// // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // 		return
// // 	}

// // 	var req schemas.LoginRequest
// // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}

// // 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}
// // 	if (h.Auth.Config.EnableEmailVerification && !user.EmailVerified) {
// // 		http.Error(w, "Email not verified", http.StatusUnauthorized)
// // 		return
// // 	}

// // 	if(h.Auth.Config.EnableTwoFactor){
// // 		if user.TwoFactorEnabled {
// // 			if user.TwoFactorVerified {
// // 				// TODO: Implement two factor verification
// // 			}
// // 		}
// // 	}

// // 	err = utils.ValidatePassword(user.Password, req.Password)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // 		return
// // 	}

// // 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// // 	if err != nil {
// // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // 		return
// // 	}

// // 	// set coookie here
// // 	http.SetCookie(w, &http.Cookie{
// // 		Name:	 h.Auth.Config.CookieName,
// // 		Value:    accessToken,
// // 		Expires:  time.Now().Add(h.Auth.Config.AccessTokenTTL),
// // 		Domain:   h.Auth.Config.CookieDomain,
// // 		Secure:   h.Auth.Config.CookieSecure,
// // 		HttpOnly: h.Auth.Config.HttpOnly,
// // 		SameSite: http.SameSiteStrictMode,
// // 		MaxAge:   h.Auth.Config.MaxCookieAge,
// // 	})

// // 	response := map[string]interface{}{
// // 		"user":          user,
// // 		"access_token":  accessToken,
// // 		"refresh_token": refreshToken,
// // 	}

// // 	w.Header().Set("Content-Type", "application/json")
// // 	w.WriteHeader(http.StatusCreated)
// // 	if err := json.NewEncoder(w).Encode(response); err != nil {
// // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // 		return
// // 	}
// // }

// // // // HandleLogout implements logout functionality
// // // func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
// // // 	if r.Method != http.MethodPost {
// // // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // // 		return
// // // 	}

// // // 	// Invalidate token logic would go here
// // // 	// Typically involves blacklisting the token or setting cookies to expire

// // // 	w.WriteHeader(http.StatusOK)
// // // 	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
// // // }

// // // // HandleRefreshToken implements token refresh functionality
// // // func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
// // // 	if r.Method != http.MethodPost {
// // // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // // 		return
// // // 	}

// // // 	var req schemas.RefreshTokenRequest
// // // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	// Validate refresh token and generate new tokens
// // // 	userId, err := utils.ValidateToken(req.RefreshToken, h.Auth.Config.JWTSecret)
// // // 	if err != nil {
// // // 		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
// // // 		return
// // // 	}

// // // 	accessToken, refreshToken, err := utils.GenerateTokens(userId, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // // 		return
// // // 	}

// // // 	response := map[string]string{
// // // 		"access_token":  accessToken,
// // // 		"refresh_token": refreshToken,
// // // 	}

// // // 	w.Header().Set("Content-Type", "application/json")
// // // 	w.WriteHeader(http.StatusOK)
// // // 	json.NewEncoder(w).Encode(response)
// // // }

// // // Additional handlers for forgot password, reset password, etc. would follow...
// // // package handlers

// // // import (
// // // 	"encoding/json"
// // // 	"net/http"

// // // 	"github.com/bete7512/goauth/models"
// // // 	"github.com/bete7512/goauth/schemas"
// // // 	"github.com/bete7512/goauth/types"
// // // 	"github.com/bete7512/goauth/utils"
// // // )

// // // type AuthHandler struct {
// // // 	Auth *types.Auth
// // // }

// // // func New(config *types.Auth) *AuthHandler {
// // // 	return &AuthHandler{Auth: config}
// // // }

// // // func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
// // // 	if r.Method != http.MethodPost {
// // // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // // 		return
// // // 	}

// // // 	var req schemas.RegisterRequest
// // // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	user := models.User{
// // // 		FirstName: req.FirstName,
// // // 		LastName:  req.LastName,
// // // 		Email:     req.Email,
// // // 	}
// // // 	hashedPassword, err := utils.HashPassword(req.Password)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}
// // // 	user.Password = hashedPassword
// // // 	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // // 		return
// // // 	}

// // // 	response := map[string]interface{}{
// // // 		"user":          user,
// // // 		"access_token":  accessToken,
// // // 		"refresh_token": refreshToken,
// // // 	}

// // // 	w.Header().Set("Content-Type", "application/json")
// // // 	w.WriteHeader(http.StatusCreated)
// // // 	if err := json.NewEncoder(w).Encode(response); err != nil {
// // // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // // 		return
// // // 	}
// // // }

// // // func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
// // // 	if r.Method != http.MethodPost {
// // // 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// // // 		return
// // // 	}

// // // 	var req schemas.LoginRequest
// // // 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	err = utils.ValidatePassword(user.Password, req.Password)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusBadRequest)
// // // 		return
// // // 	}

// // // 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// // // 	if err != nil {
// // // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // // 		return
// // // 	}

// // // 	response := map[string]interface{}{
// // // 		"user":          user,
// // // 		"access_token":  accessToken,
// // // 		"refresh_token": refreshToken,
// // // 	}

// // // 	w.Header().Set("Content-Type", "application/json")
// // // 	w.WriteHeader(http.StatusCreated)
// // // 	if err := json.NewEncoder(w).Encode(response); err != nil {
// // // 		http.Error(w, err.Error(), http.StatusInternalServerError)
// // // 		return
// // // 	}
// // // }
// // // // TODO: continue working
// // // // logout
// // // // refresh token
// // // // forgot password
// // // // reset password
// // // // update user
// // // // delete user
// // // // get user
