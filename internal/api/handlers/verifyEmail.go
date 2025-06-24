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
	"github.com/bete7512/goauth/pkg/types"
)

// HandleVerifyEmail verifies user's email with enhanced security and features
func (h *AuthRoutes) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
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
	// 	if !h.Auth.RateLimiter.Allow(clientIP, "verify_email") {
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
	req, rawData, err := h.parseVerifyEmailRequest(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Validate request
	if err := h.validateVerifyEmailRequest(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}
	// Recaptcha verification
	if h.Auth.Config.Security.Recaptcha.Enabled && h.Auth.RecaptchaManager != nil && h.Auth.Config.Security.Recaptcha.Routes[config.RouteVerifyEmail] {
		if req.RecaptchaToken == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Recaptcha token is required", nil)
			return
		}
		ip := utils.GetIpFromRequest(r)
		ok, err := h.Auth.RecaptchaManager.Verify(r.Context(), req.RecaptchaToken, ip)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Recaptcha verification failed: "+err.Error(), nil)
			return
		}
		if !ok {
			utils.RespondWithError(w, http.StatusBadRequest, "Recaptcha verification failed", nil)
			return
		}
	}

	// Get user by email
	user, err := h.getUserByEmail(r.Context(), req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Check if email is already verified (idempotency)
	if user.EmailVerified != nil && *user.EmailVerified {
		response := map[string]interface{}{
			"message": "email already verified",
			"status":  "already_verified",
		}
		if h.Auth.HookManager.GetAfterHook(config.RouteVerifyEmail) != nil && rawData != nil {
			ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
			ctx = context.WithValue(ctx, config.ResponseDataKey, response)
			r = r.WithContext(ctx)
			h.Auth.HookManager.ExecuteAfterHooks(config.RouteVerifyEmail, w, r)
			return
		}
		if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
			return
		}
		return
	}

	// Validate verification token
	token, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), user.ID, types.EmailVerificationToken)
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
	if err := h.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Token); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrInvalidToken, err)
		return
	}

	// Mark token as used to prevent replay attacks
	if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), token.ID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, responseErrors.ErrInternalError, err)
		return
	}

	// Mark email as verified
	emailVerified := true
	activated := true
	user.EmailVerified = &emailVerified
	user.Active = &activated
	user.UpdatedAt = time.Now()
	verifiedAt := time.Now()
	user.EmailVerifiedAt = &verifiedAt
	if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to verify email: "+err.Error(), err)
		return
	}

	// Revoke verification token
	if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), token.ID); err != nil {
		h.Auth.Logger.Errorf("Failed to revoke verification token %d: %v", token.ID, err)
	}

	// Generate response based on method
	response, err := h.generateVerificationResponse(r.Context(), r.Method, user, w)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	// Send welcome email asynchronously (only for first-time verification)
	h.sendWelcomeEmailAsync(r.Context(), user)
	if h.Auth.HookManager.GetAfterHook(config.RouteVerifyEmail) != nil && rawData != nil {
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		ctx = context.WithValue(ctx, config.ResponseDataKey, response)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteVerifyEmail, w, r)
		return
	}

	if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
	}
}

// parseVerifyEmailRequest parses the request and handles hooks
func (h *AuthRoutes) parseVerifyEmailRequest(r *http.Request) (*schemas.VerifyEmailRequest, map[string]interface{}, error) {
	var req schemas.VerifyEmailRequest
	var rawData map[string]interface{}

	if r.Method == http.MethodGet {
		req.Token = strings.TrimSpace(r.URL.Query().Get("token"))
		req.Email = strings.TrimSpace(r.URL.Query().Get("email"))
		return &req, nil, nil
	}

	// Handle POST request with potential hooks
	if h.Auth.HookManager.GetAfterHook(config.RouteVerifyEmail) != nil {
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
	req.Token = strings.TrimSpace(req.Token)
	req.Email = strings.TrimSpace(req.Email)
	req.RecaptchaToken = strings.TrimSpace(req.RecaptchaToken)

	return &req, rawData, nil
}

// validateVerifyEmailRequest validates the verification request
func (h *AuthRoutes) validateVerifyEmailRequest(req *schemas.VerifyEmailRequest) error {
	if req.Token == "" {
		return errors.New("token is required")
	}
	if req.Email == "" {
		return errors.New("email is required")
	}
	return nil
}

// generateVerificationResponse creates the appropriate response based on request method
func (h *AuthRoutes) generateVerificationResponse(ctx context.Context, method string, user *types.User, w http.ResponseWriter) (map[string]interface{}, error) {
	baseResponse := map[string]interface{}{
		"message": "email verified successfully",
		"user": map[string]interface{}{
			"id":             user.ID,
			"email":          user.Email,
			"email_verified": true,
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
		if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedRefreshToken, types.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL); err != nil {
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

// sendWelcomeEmailAsync sends welcome email in background
func (h *AuthRoutes) sendWelcomeEmailAsync(ctx context.Context, user *types.User) {
	if !h.Auth.Config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		return
	}

	h.Auth.WorkerPool.Submit(func() {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		if err := h.Auth.Config.Email.Sender.CustomSender.SendWelcomeEmail(ctx, *user); err != nil {
			h.Auth.Logger.Errorf("Failed to send welcome email to user %s: %v", user.ID, err)
		} else {
			h.Auth.Logger.Infof("Welcome email sent successfully to user %s", user.ID)
		}
	})
}
