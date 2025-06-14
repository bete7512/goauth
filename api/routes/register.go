package routes

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

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/bete7512/goauth/types"
	"github.com/bete7512/goauth/utils"
	"gorm.io/gorm"
)

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
