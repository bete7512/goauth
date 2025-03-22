package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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
		if h.Auth.HookManager != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
				return
			}
		}
		handler(w, r)
	}
}

// HandleRegister handles user registration
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req schemas.RegisterRequest
	// Then your hook can access both
	if h.Auth.HookManager.GetAfterHook(types.RouteRegister) != nil {
		var rawData map[string]interface{}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		// First, decode into the map to get all fields
		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			http.Error(w, "Invalid request body JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, "Invalid request format: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(r.Context(), "request_data", rawData)
		r = r.WithContext(ctx)
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
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
		SigninVia:        "email",
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

			err = h.Auth.Config.EmailSender.SendVerification(user, verificationURL)
			if err != nil {
				// Log error but continue - user can request verification email later
				fmt.Printf("Failed to send verification email: %v\n", err)
			}
		}
	}
	// Set access token cookie
	if !h.Auth.Config.EnableEmailVerification {
		accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.Cookie.AccessTokenTTL,h.Auth.Config.Cookie.RefreshTokenTTL, h.Auth.Config.JWTSecret)
		if err != nil {
			http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
			return
		}

		// Save refresh token
		err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.Cookie.RefreshTokenTTL)
		if err != nil {
			http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     h.Auth.Config.Cookie.CookieName,
			Value:    accessToken,
			Expires:  time.Now().Add(h.Auth.Config.Cookie.AccessTokenTTL),
			Domain:   h.Auth.Config.Cookie.CookieDomain,
			Path:     h.Auth.Config.Cookie.CookiePath,
			Secure:   h.Auth.Config.Cookie.CookieSecure,
			HttpOnly: h.Auth.Config.Cookie.HttpOnly,
			SameSite: h.Auth.Config.Cookie.SameSite,
			MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "___goauth_refresh_token_" + h.Auth.Config.Cookie.CookieName,
			Value:    refreshToken,
			Expires:  time.Now().Add(h.Auth.Config.Cookie.RefreshTokenTTL),
			Domain:   h.Auth.Config.Cookie.CookieDomain,
			Path:     h.Auth.Config.Cookie.CookiePath,
			Secure:   h.Auth.Config.Cookie.CookieSecure,
			HttpOnly: h.Auth.Config.Cookie.HttpOnly,
			SameSite: h.Auth.Config.Cookie.SameSite,
			MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
		})
	}

	// Prepare response
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	//TODO: make able to send Send response

	if h.Auth.HookManager.GetAfterHook(types.RouteRegister) != nil {
		log.Println("HookManager is not nil")
		ctx := context.WithValue(r.Context(), "response_data", userResponse)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(types.RouteRegister, w, r)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(userResponse); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
			return
		}
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
		if err.Error() == "user not found" {
			http.Error(w, "User Not Found", http.StatusUnauthorized)
			return
		}
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
	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.Cookie.AccessTokenTTL,h.Auth.Config.Cookie.RefreshTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate authentication tokens", http.StatusInternalServerError)
		return
	}

	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.Cookie.RefreshTokenTTL)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.Cookie.AccessTokenTTL),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: h.Auth.Config.Cookie.SameSite,
		MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.Cookie.RefreshTokenTTL),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: h.Auth.Config.Cookie.SameSite,
		MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
	})

	if h.Auth.HookManager.GetAfterHook(types.RouteLogin) != nil {
		ctx := context.WithValue(r.Context(), "response_data", schemas.UserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		})
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(types.RouteLogin, w, r)
	} else {
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

}

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from cookie or Authorization header
	token := extractToken(r, h.Auth.Config.Cookie.CookieName)
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
		Name:     "___goauth_access_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: h.Auth.Config.Cookie.SameSite,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		SameSite: h.Auth.Config.Cookie.SameSite,
		Secure:   true,
		HttpOnly: true,
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


	token := extractToken(r, "___goauth_refresh_token_"+h.Auth.Config.Cookie.CookieName)
	if token == "" {
		http.Error(w, "No refresh token provided", http.StatusBadRequest)
		return
	}

	// Validate refresh token
	claims, err := utils.ValidateToken(token, h.Auth.Config.JWTSecret)
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
	valid, err := h.Auth.Repository.GetTokenRepository().ValidateRefreshToken(userID, token)
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
	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.Cookie.AccessTokenTTL,h.Auth.Config.Cookie.RefreshTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Invalidate old refresh token
	h.Auth.Repository.GetTokenRepository().InvalidateRefreshToken(userID, token)

	// Save new refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.Cookie.RefreshTokenTTL)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.Cookie.AccessTokenTTL),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: h.Auth.Config.Cookie.SameSite,
		MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
	})
	// 		Name:     "___goauth_refresh_token_" + h.Auth.Config.CookieName,

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.Cookie.CookieName,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.Cookie.RefreshTokenTTL),
		Domain:   h.Auth.Config.Cookie.CookieDomain,
		Path:     h.Auth.Config.Cookie.CookiePath,
		Secure:   h.Auth.Config.Cookie.CookieSecure,
		HttpOnly: h.Auth.Config.Cookie.HttpOnly,
		SameSite: h.Auth.Config.Cookie.SameSite,
		MaxAge:   h.Auth.Config.Cookie.MaxCookieAge,
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
	// TODO: make configurable to get token from header
	// bearerToken := r.Header.Get("Authorization")
	// if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
	// 	return bearerToken[7:]
	// }

	return ""
}
