package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	responseErrors "github.com/bete7512/goauth/internal/api/handlers/errors"
	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

// HandleVerifyPhone verifies user's phone with enhanced security and features
func (h *AuthRoutes) HandleVerifyPhone(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Method validation
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, responseErrors.ErrMethodNotAllowed, nil)
		return
	}

	//TODO: add  Rate limiting for verification attempts
	// clientIP := utils.GetIpFromRequest(r)
	// if h.Auth.RateLimiter != nil {
	// 	if !h.Auth.RateLimiter.Allow(clientIP, "verify_phone") {
	// 		utils.RespondWithError(w, http.StatusTooManyRequests, responseErrors.ErrTooManyRequests, nil)
	// 		return
	// 	}
	// }

	//TODO: add CSRF protection for POST requests
	// if r.Method == http.MethodPost && h.Auth.CSRFManager != nil {
	// 	if !h.Auth.CSRFManager.ValidateToken(r) {
	// 		utils.RespondWithError(w, http.StatusForbidden, responseErrors.ErrInvalidCSRF, nil)
	// 		return
	// 	}
	// }

	// Parse request based on method
	req, rawData, err := h.parseVerifyPhoneRequest(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Validate request
	if req.Code == "" || req.PhoneNumber == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "verification code and phone number are required", nil)
		return
	}
	// Recaptcha verification
	// if h.Auth.Config.Security.Recaptcha.Enabled && h.Auth.RecaptchaManager != nil && h.Auth.Config.Security.Recaptcha.Routes[config.RouteVerifyPhone] {
	// 	if req.RecaptchaToken == "" {
	// 		utils.RespondWithError(w, http.StatusBadRequest, "Recaptcha token is required", nil)
	// 		return
	// 	}
	// 	ip := utils.GetIpFromRequest(r)
	// 	ok, err := h.Auth.RecaptchaManager.Verify(r.Context(), req.RecaptchaToken, ip)
	// 	if err != nil {
	// 		utils.RespondWithError(w, http.StatusInternalServerError, "Recaptcha verification failed: "+err.Error(), nil)
	// 		return
	// 	}
	// 	if !ok {
	// 		utils.RespondWithError(w, http.StatusBadRequest, "Recaptcha verification failed", nil)
	// 		return
	// 	}
	// }

	// Get user by phone number or authenticated user
	user, err := h.getUserByPhoneNumber(r.Context(), req.PhoneNumber)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Check if phone is already verified (idempotency)
	if user.PhoneVerified != nil && *user.PhoneVerified {
		response := map[string]interface{}{
			"message": "phone already verified",
			"status":  "already_verified",
		}
		if h.Auth.HookManager.GetAfterHook(config.RouteVerifyPhone) != nil && rawData != nil {
			ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
			ctx = context.WithValue(ctx, config.ResponseDataKey, response)
			r = r.WithContext(ctx)
			h.Auth.HookManager.ExecuteAfterHooks(config.RouteVerifyPhone, w, r)
			return
		}
		if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
			return
		}
		return
	}

	// Validate verification token
	token, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), user.ID, models.PhoneVerificationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrInvalidToken, err)
		return
	}
	if token == nil {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrTokenNotFound, nil)
		return
	}

	// Check if token was already used (replay protection)
	if token.Used != nil && *token.Used {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrTokenAlreadyUsed, nil)
		return
	}

	// Validate token hash
	if err := h.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Code); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrInvalidToken, err)
		return
	}

	// Mark token as used to prevent replay attacks
	if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), token.ID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, responseErrors.ErrInternalError, err)
		return
	}

	// Mark phone as verified
	phoneVerified := true
	user.PhoneVerified = &phoneVerified
	activated := true
	user.Active = &activated
	verifiedAt := time.Now()
	user.PhoneVerifiedAt = &verifiedAt

	if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to verify phone: "+err.Error(), err)
		return
	}

	// Revoke verification token
	if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), token.ID); err != nil {
		h.Auth.Logger.Errorf("Failed to revoke verification token %d: %v", token.ID, err)
	}

	// Generate response based on method
	response, err := h.generatePhoneVerificationResponse(r.Context(), r.Method, user, w)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	// Send welcome SMS asynchronously (only for first-time verification)
	if h.Auth.HookManager.GetAfterHook(config.RouteVerifyPhone) != nil && rawData != nil {
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		ctx = context.WithValue(ctx, config.ResponseDataKey, response)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteVerifyPhone, w, r)
		return
	}

	if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
	}
}

// parseVerifyPhoneRequest parses the request and handles hooks
func (h *AuthRoutes) parseVerifyPhoneRequest(r *http.Request) (*schemas.VerifyPhoneRequest, map[string]interface{}, error) {
	var req schemas.VerifyPhoneRequest
	var rawData map[string]interface{}

	if r.Method == http.MethodGet {
		req.Code = strings.TrimSpace(r.URL.Query().Get("code"))
		req.PhoneNumber = strings.TrimSpace(r.URL.Query().Get("phone_number"))
		return &req, nil, nil
	}

	// Handle POST request with potential hooks
	if h.Auth.HookManager.GetAfterHook(config.RouteVerifyPhone) != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, errors.New("failed to read request body: " + err.Error())
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			return nil, nil, errors.New("invalid request body JSON: " + err.Error())
		}

		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			return nil, nil, errors.New("invalid request format: " + err.Error())
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, nil, errors.New("invalid request body: " + err.Error())
		}
	}

	// Sanitize input
	req.Code = strings.TrimSpace(req.Code)
	req.PhoneNumber = strings.TrimSpace(req.PhoneNumber)
	// req.RecaptchaToken = strings.TrimSpace(req.RecaptchaToken)

	return &req, rawData, nil
}

// generatePhoneVerificationResponse creates the appropriate response based on request method
func (h *AuthRoutes) generatePhoneVerificationResponse(ctx context.Context, method string, user *models.User, w http.ResponseWriter) (map[string]interface{}, error) {
	baseResponse := map[string]interface{}{
		"message": "phone verified successfully",
		"user": map[string]interface{}{
			"id":             user.ID,
			"phone_number":   user.PhoneNumber,
			"phone_verified": true,
		},
	}

	if method == http.MethodPost {
		// Generate authentication tokens
		accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
		if err != nil {
			return nil, errors.New("failed to generate tokens")
		}

		hashedRefreshToken, err := h.Auth.TokenManager.HashToken(refreshToken)
		if err != nil {
			return nil, errors.New("failed to hash refresh token")
		}
		// Save refresh token with correct type and TTL
		if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedRefreshToken, models.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL); err != nil {
			return nil, errors.New("failed to save refresh token")
		}

		// Set secure access token cookie
		h.setAccessTokenCookie(w, accessToken)

		// Add tokens to response
		baseResponse["access_token"] = accessToken
		baseResponse["refresh_token"] = refreshToken
		baseResponse["token_type"] = "Bearer"
		baseResponse["expires_in"] = int(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds())
	}

	return baseResponse, nil
}
