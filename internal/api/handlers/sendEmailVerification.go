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

// HandleResendEmailVerification handles resending email verification with enhanced security
func (h *AuthRoutes) HandleSendEmailVerification(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Method validation
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, responseErrors.ErrMethodNotAllowed, nil)
		return
	}

	//TODO: ADD RATE LIMITING FOR RESEND ATTEMPTS
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

	// Parse request with hook support
	req, rawData, err := h.parseSendEmailVerificationRequest(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if req.Email == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "email is required", nil)
		return
	}

	// Get user by email
	user, err := h.getUserByEmail(r.Context(), req.Email)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}
	// Check if email is already verified
	if user.EmailVerified != nil && *user.EmailVerified {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrEmailAlreadyVerified, nil)
		return
	}

	existingToken, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), user.ID, models.EmailVerificationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to get existing verification token", err)
		return
	}

	// Revoke existing verification tokens
	if existingToken != nil {
		if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), existingToken.ID); err != nil {
			h.Auth.Logger.Errorf("Failed to revoke existing tokens for user %s: %v", user.ID, err)
		}
	}

	// Generate new verification token
	verificationToken, hashedToken, err := h.generateVerificationToken()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate verification token", err)
		return
	}

	// Save verification token
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, hashedToken, models.EmailVerificationToken, h.Auth.Config.AuthConfig.Tokens.EmailVerificationTTL); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save verification token", err)
		return
	}

	// Send verification email asynchronously
	if err := h.sendVerificationEmailAsync(r.Context(), user, verificationToken); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send verification email", err)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"message": "verification email sent successfully",
		"status":  "sent",
		"email":   user.Email,
	}

	if h.Auth.HookManager.GetAfterHook(config.RouteSendEmailVerification) != nil && rawData != nil {
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		ctx = context.WithValue(ctx, config.ResponseDataKey, response)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteSendEmailVerification, w, r)
		return
	}

	if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
	}
}

// parseResendVerificationRequest parses the request with hook support
func (h *AuthRoutes) parseSendEmailVerificationRequest(r *http.Request) (*schemas.SendVerificationEmailRequest, map[string]interface{}, error) {
	var req schemas.SendVerificationEmailRequest
	var rawData map[string]interface{}

	// Handle hooks that need raw data
	if h.Auth.HookManager.GetAfterHook(config.RouteSendEmailVerification) != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, errors.New("failed to read request body: " + err.Error())
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			return nil, nil, errors.New("invalid request body json: " + err.Error())
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
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	return &req, rawData, nil
}

// generateVerificationToken generates a new verification token pair
func (h *AuthRoutes) generateVerificationToken() (string, string, error) {
	verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return "", "", err
	}

	hashedToken, err := h.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		return "", "", err
	}

	return verificationToken, hashedToken, nil
}

// sendVerificationEmailAsync sends verification email in background
func (h *AuthRoutes) sendVerificationEmailAsync(ctx context.Context, user *models.User, verificationToken string) error {
	// Construct verification URL
	verificationURL := h.Auth.Config.AuthConfig.Methods.EmailVerification.VerificationURL + "?token=" + verificationToken + "&email=" + user.Email

	// Send email asynchronously
	h.Auth.WorkerPool.Submit(func() {
		emailCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		h.Auth.Logger.Infof("Sending verification email to user %s: %s", user.ID, verificationToken)
		if err := h.Auth.Config.Email.Sender.CustomSender.SendVerificationEmail(emailCtx, *user, verificationURL); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification email to user %s: %v", user.ID, err)
		} else {
			h.Auth.Logger.Infof("Verification email sent successfully to user %s", user.ID)
		}
	})

	return nil
}
