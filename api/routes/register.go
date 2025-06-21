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
	"strings"
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
		ctx := context.WithValue(r.Context(), types.RequestDataKey, rawData)
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
	req.Email = strings.ToLower(req.Email)
	if err := h.ValidateEmail(req.Email); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	if err := h.ValidatePhoneNumber(req.PhoneNumber); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Check if email already exists
	existingUser, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to check if email exists: "+err.Error(), nil)
		h.Auth.Logger.Error("Failed to check if email exists: " + err.Error())
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
		Active:           true,
		TwoFactorEnabled: false,
		SignedUpVia:      "email",
		PhoneNumber:      req.PhoneNumber,
	}
	if h.Auth.Config.AuthConfig.EnablePhoneNumberVerificationOnSignup || h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup {
		user.PhoneVerified = false
		user.Active = false
		user.EmailVerified = false
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
	if h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup {
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
			verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
				h.Auth.Config.AuthConfig.EmailVerificationURL,
				verificationToken,
				user.Email)

			err = h.Auth.Config.EmailSender.SendVerification(user, verificationURL)
			if err != nil {
				log.Printf("Failed to send verification email: %v\n", err)
			}
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Email sender not configured", nil)
			return
		}
	}
	if h.Auth.Config.AuthConfig.EnablePhoneNumberVerificationOnSignup {
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
		err = h.Auth.Repository.GetTokenRepository().SaveToken(user.ID, hashedOTP, models.PhoneVerificationToken, h.Auth.Config.PhoneVerificationTokenTTL)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save verification code", nil)
			return
		}
		if h.Auth.Config.SMSSender != nil {
			err = h.Auth.Config.SMSSender.SendTwoFactorCode(user, OTP)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send verification SMS", nil)
				return
			}
		}

	}

	// Handle verification responses
	if h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup || h.Auth.Config.AuthConfig.EnablePhoneNumberVerificationOnSignup {
		var message string
		if h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup && h.Auth.Config.AuthConfig.EnablePhoneNumberVerificationOnSignup {
			message = "Verification Links and codes sent to email and phone number"
		} else if h.Auth.Config.AuthConfig.EnableEmailVerificationOnSignup {
			message = "Verification Link sent to email"
		} else {
			message = "Verification OTP sent to phone number"
		}

		response := map[string]interface{}{
			"user": map[string]interface{}{
				"id":             user.ID,
				"first_name":     user.FirstName,
				"last_name":      user.LastName,
				"email":          user.Email,
				"phone_number":   user.PhoneNumber,
				"email_verified": user.EmailVerified,
				"phone_verified": user.PhoneVerified,
				"active":         user.Active,
				"signin_via":     user.SignedUpVia,
				"created_at":     user.CreatedAt,
			},
			"message": message,
		}

		if h.Auth.HookManager.GetAfterHook(types.RouteRegister) != nil {
			ctx := context.WithValue(r.Context(), types.ResponseDataKey, response)
			r = r.WithContext(ctx)
			h.Auth.HookManager.ExecuteAfterHooks(types.RouteRegister, w, r)
			return
		} else {
			err := utils.RespondWithJSON(w, http.StatusCreated, response)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send response", nil)
				return
			}
		}
		return
	}

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
	// Prepare response
	userResponse := map[string]interface{}{
		"id":           user.ID,
		"first_name":   user.FirstName,
		"last_name":    user.LastName,
		"email":        user.Email,
		"created_at":   user.CreatedAt,
		"phone_number": user.PhoneNumber,
	}

	if h.Auth.HookManager.GetAfterHook(types.RouteRegister) != nil {
		ctx := context.WithValue(r.Context(), types.ResponseDataKey, userResponse)
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
