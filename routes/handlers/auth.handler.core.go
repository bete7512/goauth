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
	"strings"
	"time"
	"unicode"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/types"
	"github.com/bete7512/goauth/utils"
	"gorm.io/gorm"
)

type AuthHandler struct {
	Auth *types.Auth
}

func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Auth.HookManager != nil && h.Auth.HookManager.GetBeforeHook(route) != nil {
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
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	var req schemas.RegisterRequest
	// Then your hook can access both
	if h.Auth.HookManager.GetAfterHook(types.RouteRegister) != nil {
		var rawData map[string]interface{}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error(), nil)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body JSON: "+err.Error(), nil)
			return
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request format: "+err.Error(), nil)
			return
		}
		ctx := context.WithValue(r.Context(), "request_data", rawData)
		r = r.WithContext(ctx)
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
			return
		}
	}

	// Validate password against policy
	if err := h.validatePasswordPolicy(req.Password, h.Auth.Config.PasswordPolicy); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Check if email already exists
	existingUser, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to check if email exists: "+err.Error(), nil)
		return
	}
	if existingUser != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Email already exists", nil)
		return
	}

	// Create user object
	user := models.User{
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		Email:            req.Email,
		EmailVerified:    !h.Auth.Config.AuthConfig.EnableEmailVerification,
		Active:           true,
		TwoFactorEnabled: false,
		SigninVia:        "email",
	}

	// Hash password
	hashedPassword, err := h.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to secure password: "+err.Error(), nil)
		return
	}
	user.Password = hashedPassword

	// Create user in database
	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create user: "+err.Error(), nil)
		return
	}

	// Handle email verification if enabled
	if h.Auth.Config.AuthConfig.EnableEmailVerification {
		verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate verification token", nil)
			return
		}

		// Save verification token
		err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, verificationToken, models.EmailVerificationToken, 24*time.Hour)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification token", nil)
			return
		}

		// Send verification email
		if h.Auth.Config.EmailSender != nil {
			verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
				h.Auth.Config.AuthConfig.EmailVerificationURL,
				verificationToken,
				user.Email)

			err = h.Auth.Config.EmailSender.SendVerification(user, verificationURL)
			if err != nil {
				log.Printf("Failed to send verification email: %v\n", err)
			}
		}
	}
	// Set access token cookie
	if !h.Auth.Config.AuthConfig.EnableEmailVerification {
		accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(&user)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate authentication tokens", nil)
			return
		}

		// Save refresh token
		err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", nil)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     h.Auth.Config.AuthConfig.Cookie.Name,
			Value:    accessToken,
			Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.AccessTokenTTL),
			Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
			Path:     h.Auth.Config.AuthConfig.Cookie.Path,
			Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
			HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
			SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
			MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
			Value:    refreshToken,
			Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL),
			Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
			Path:     h.Auth.Config.AuthConfig.Cookie.Path,
			Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
			HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
			SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
			MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
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
		ctx := context.WithValue(r.Context(), "response_data", userResponse)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(types.RouteRegister, w, r)
		return
	} else {
		err := utils.RespondWithJSON(w, http.StatusCreated, userResponse)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
			return
		}
	}

}

// HandleLogin handles user login
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	var req schemas.LoginRequest
	// Then your hook can access both
	if h.Auth.HookManager.GetAfterHook(types.RouteLogin) != nil {
		var rawData map[string]interface{}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error(), nil)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body JSON: "+err.Error(), nil)
			return
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request format: "+err.Error(), nil)
			return
		}
		ctx := context.WithValue(r.Context(), "request_data", rawData)
		r = r.WithContext(ctx)
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error(), nil)
			return
		}
	}

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		if err.Error() == "user not found" {
			utils.RespondWithError(w, http.StatusUnauthorized, "User Not Found", nil)
			return
		}

		log.Println("Error getting user by email:", err)
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password", err)
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password", nil)
		return
	}
	if !user.Active {
		utils.RespondWithError(w, http.StatusUnauthorized, "Account is deactivated", nil)
		return
	}

	err = h.Auth.TokenManager.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid email or password", err)
		return
	}

	// Handle two-factor authentication if enabled
	if h.Auth.Config.AuthConfig.EnableTwoFactor && user.TwoFactorEnabled {
		if req.TwoFactorCode == "" {
			err = h.sendTwoFactorCode(user)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send two-factor code", nil)
				return
			}
			err := utils.RespondWithJSON(
				w,
				http.StatusOK,
				map[string]interface{}{
					"message":           "Two-factor code sent",
					"requires_2fa":      true,
					"two_factor_method": h.Auth.Config.AuthConfig.TwoFactorMethod,
				},
			)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
				return
			}
			return
		} else {
			twoFactorTTl := 10 * time.Minute
			err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, req.TwoFactorCode, models.TwoFactorCode, twoFactorTTl)
			if err != nil {
				utils.RespondWithError(w, http.StatusUnauthorized, "Invalid two-factor code", nil)
				return
			}
		}
	}

	accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate authentication tokens", nil)
		return
	}

	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
	// SaveRefreshToken(user.ID, refreshToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", nil)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:   accessToken,
		Expires: time.Now().Add(h.Auth.Config.AuthConfig.Cookie.AccessTokenTTL),
		// Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})
	if h.Auth.HookManager.GetAfterHook(types.RouteLogin) != nil {

		ctx := context.WithValue(r.Context(), "response_data", map[string]interface{}{
			"id":            user.ID,
			"user":          user,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})

		log.Println("Executing after login hook")
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(types.RouteLogin, w, r)
	} else {
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
		err := utils.RespondWithJSON(w, http.StatusOK, response)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
			return
		}
	}

}

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	token := h.extractToken(r, h.Auth.Config.AuthConfig.Cookie.Name)
	if token == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "No authentication token provided", nil)
		return
	}
	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid authentication token", nil)
		return
	}
	userID := claims["user_id"].(string)
	err = h.Auth.Repository.GetTokenRepository().InvalidateAllTokens(userID, models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh tokens", nil)
		return
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   -1,
	})

	err = utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Successfully logged out",
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}

// HandleRefreshToken handles token refresh
func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	token := h.extractToken(r, "___goauth_refresh_token_"+h.Auth.Config.AuthConfig.Cookie.Name)
	if token == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "No refresh token provided", nil)
		return
	}

	// Validate refresh token
	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token", nil)
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid refresh token claims", nil)
		return
	}

	valid, err := h.Auth.Repository.GetTokenRepository().ValidateTokenWithUserID(userID, token, models.RefreshToken)
	if err != nil || !valid {
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token", nil)
		return
	}

	// Get user
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "User not found", nil)
		return
	}

	// Check if user is active
	if !user.Active {
		utils.RespondWithError(w, http.StatusUnauthorized, "Account is deactivated", nil)
		return
	}

	// Generate new tokens
	accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate tokens", nil)
		return
	}

	err = h.Auth.Repository.GetTokenRepository().InvalidateToken(userID, token, models.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to invalidate refresh token", nil)
		return
	}

	// Save new refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, refreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save refresh token", nil)
		return
	}

	// Clear cookie regardless of token validity
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})
	// 		Name:     "___goauth_refresh_token_" + h.Auth.Config.CookieName,

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.Cookie.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})

	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	err = utils.RespondWithJSON(w, http.StatusOK, response)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}

// HandleGetUser returns the current user's profile
func (h *AuthHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	// Authenticate user
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWTSecret)
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

	// Prepare user response
	userResponse := schemas.UserResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}
	err = utils.RespondWithJSON(w, http.StatusOK, userResponse)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
		return
	}
}

// Helper functions

// validatePasswordPolicy validates a password against the configured policy
func (h *AuthHandler) validatePasswordPolicy(password string, policy types.PasswordPolicy) error {
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
func (h *AuthHandler) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
	token := h.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := h.Auth.TokenManager.ValidateToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (h *AuthHandler) extractToken(r *http.Request, cookieName string) string {
	if cookieName != "" {
		cookie, err := r.Cookie("___goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}
	if h.Auth.Config.AuthConfig.EnableBearerAuth {
		bearerToken := r.Header.Get("Authorization")
		if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
			return bearerToken[7:]
		}

	}

	return ""
}
