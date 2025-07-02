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

// HandleSendPhoneVerification handles sending phone verification code with enhanced security
func (h *AuthRoutes) HandleSendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Method validation
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, responseErrors.ErrMethodNotAllowed, nil)
		return
	}

	//TODO: ADD RATE LIMITING FOR PHONE VERIFICATION ATTEMPTS
	// clientIP := utils.GetIpFromRequest(r)
	// if h.Auth.RateLimiter != nil {
	// 	if !h.Auth.RateLimiter.Allow(clientIP, "send_phone_verification") {
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
	req, rawData, err := h.parsePhoneVerificationRequest(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if req.PhoneNumber == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "phone number is required", nil)
		return
	}

	// Get user - either by authentication or by phone number
	var user *models.User

	// Try to get authenticated user first
	userID, err := h.authenticateRequest(r, h.Auth.Config.AuthConfig.Cookie.Name, h.Auth.Config.AuthConfig.JWT.Secret)
	if err == nil && userID != "" {
		user, err = h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
		if err != nil {
			h.Auth.Logger.Infof("Failed to get user by ID: %v", err)
		}
	}

	// If no authenticated user, try to find by phone number
	if user == nil {
		user, err = h.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(r.Context(), req.PhoneNumber)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "user not found", err)
			return
		}
	}

	if user == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "user not found", nil)
		return
	}

	// Validate phone number exists for user
	if user.PhoneNumber == nil || *user.PhoneNumber == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "phone number not found for user", nil)
		return
	}

	// Check if phone is already verified
	if user.PhoneVerified != nil && *user.PhoneVerified {
		utils.RespondWithError(w, http.StatusBadRequest, responseErrors.ErrPhoneAlreadyVerified, nil)
		return
	}

	existingToken, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), user.ID, models.PhoneVerificationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to get existing verification token", err)
		return
	}

	// Revoke existing phone verification tokens
	if existingToken != nil {
		if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), existingToken.ID); err != nil {
			h.Auth.Logger.Errorf("Failed to revoke existing phone tokens for user %s: %v", user.ID, err)
		}
	}

	// Generate verification code (OTP)
	verificationCode, hashedCode, err := h.generatePhoneVerificationCode()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate verification code", err)
		return
	}

	// Save verification code
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, hashedCode, models.PhoneVerificationToken, h.Auth.Config.AuthConfig.Tokens.PhoneVerificationTTL); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save verification code", err)
		return
	}

	// Send verification SMS asynchronously
	if err := h.sendPhoneVerificationSMSAsync(r.Context(), user, verificationCode); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send verification SMS", err)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"message":      "verification code sent successfully",
		"status":       "sent",
		"phone_number": maskPhoneNumber(*user.PhoneNumber),
	}

	if h.Auth.HookManager.GetAfterHook(config.RouteSendPhoneVerification) != nil && rawData != nil {
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		ctx = context.WithValue(ctx, config.ResponseDataKey, response)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteSendPhoneVerification, w, r)
		return
	}

	if err := utils.RespondWithJSON(w, http.StatusOK, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", err)
	}
}

// parsePhoneVerificationRequest parses the request with hook support
func (h *AuthRoutes) parsePhoneVerificationRequest(r *http.Request) (*schemas.SendPhoneVerificationRequest, map[string]interface{}, error) {
	var req schemas.SendPhoneVerificationRequest
	var rawData map[string]interface{}

	// Handle hooks that need raw data
	if h.Auth.HookManager.GetAfterHook(config.RouteSendPhoneVerification) != nil {
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
	req.PhoneNumber = strings.TrimSpace(req.PhoneNumber)

	return &req, rawData, nil
}

// generatePhoneVerificationCode generates a new phone verification code pair
func (h *AuthRoutes) generatePhoneVerificationCode() (string, string, error) {
	verificationCode, err := h.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return "", "", err
	}

	hashedCode, err := h.Auth.TokenManager.HashToken(verificationCode)
	if err != nil {
		return "", "", err
	}

	return verificationCode, hashedCode, nil
}

// sendPhoneVerificationSMSAsync sends verification SMS in background
func (h *AuthRoutes) sendPhoneVerificationSMSAsync(ctx context.Context, user *models.User, verificationCode string) error {
	// Send SMS asynchronously
	h.Auth.WorkerPool.Submit(func() {
		smsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		if h.Auth.Config.SMS.CustomSender != nil {
			h.Auth.Logger.Infof("Sending verification SMS to user %s: %s", user.ID, verificationCode)
			if err := h.Auth.Config.SMS.CustomSender.SendTwoFactorSMS(smsCtx, *user, verificationCode); err != nil {
				h.Auth.Logger.Errorf("Failed to send verification SMS to user %s: %v", user.ID, err)
			} else {
				h.Auth.Logger.Infof("Verification SMS sent successfully to user %s", user.ID)
			}
		} else {
			h.Auth.Logger.Warnf("SMS sender not configured, verification code for user %s: %s", user.ID, verificationCode)
		}
	})

	return nil
}

// maskPhoneNumber masks phone number for security (e.g., +1234****567)
func maskPhoneNumber(phoneNumber string) string {
	if len(phoneNumber) < 4 {
		return "****"
	}

	if len(phoneNumber) <= 7 {
		return phoneNumber[:2] + "****" + phoneNumber[len(phoneNumber)-1:]
	}

	return phoneNumber[:4] + "****" + phoneNumber[len(phoneNumber)-3:]
}
