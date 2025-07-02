package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	responseErrors "github.com/bete7512/goauth/internal/api/handlers/errors"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/models"

	"gorm.io/gorm"
)

// setupEmailVerification sets up email verification for a user
func (h *AuthRoutes) setupEmailVerification(ctx context.Context, user *models.User) error {
	if h.Auth.Config.Email.Sender.CustomSender == nil {
		return errors.New("email sender not configured")
	}

	// Generate verification token
	verificationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	hashedVerificationToken, err := h.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		return fmt.Errorf("failed to hash verification token: %w", err)
	}

	// Save verification token
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedVerificationToken, models.EmailVerificationToken, h.Auth.Config.AuthConfig.Tokens.EmailVerificationTTL); err != nil {
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification email asynchronously
	verificationURL := fmt.Sprintf("%s?token=%s&email=%s",
		h.Auth.Config.AuthConfig.Methods.EmailVerification.VerificationURL,
		verificationToken,
		user.Email)

	h.Auth.Logger.Infof("Sending verification email to user %d: %s", user.ID, verificationToken)
	h.Auth.WorkerPool.Submit(func() {
		if err := h.Auth.Config.Email.Sender.CustomSender.SendVerificationEmail(context.Background(), *user, verificationURL); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification email to user %d: %v", user.ID, err)
		}
	})

	return nil
}

// setupPhoneVerification sets up phone verification for a user
func (h *AuthRoutes) setupPhoneVerification(ctx context.Context, user *models.User) error {
	if h.Auth.Config.SMS.CustomSender == nil {
		return errors.New("SMS sender not configured")
	}

	// Generate OTP
	otp, err := h.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate verification OTP: %w", err)
	}

	hashedOTP, err := h.Auth.TokenManager.HashToken(otp)
	if err != nil {
		return fmt.Errorf("failed to hash verification OTP: %w", err)
	}

	// Save verification token
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedOTP, models.PhoneVerificationToken, h.Auth.Config.AuthConfig.Tokens.PhoneVerificationTTL); err != nil {
		return fmt.Errorf("failed to save verification OTP: %w", err)
	}

	h.Auth.Logger.Infof("Sending verification SMS to user %d: %s", user.ID, otp)
	// Send verification SMS asynchronously (fixed: removed duplicate sending)
	h.Auth.WorkerPool.Submit(func() {
		if err := h.Auth.Config.SMS.CustomSender.SendTwoFactorSMS(context.Background(), *user, otp); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification SMS to user %d: %v", user.ID, err)
		}
	})

	return nil
}

// getUserByEmail retrieves user by email with proper error handling
func (h *AuthRoutes) getUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New(responseErrors.ErrUserNotFound)
		}
		return nil, errors.New(responseErrors.ErrInternalError)
	}

	if user == nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	return user, nil
}

// getUserByPhoneNumber retrieves user by phone number with proper error handling
func (h *AuthRoutes) getUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	// Try to get authenticated user first
	user, err := h.Auth.Repository.GetUserRepository().GetUserByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	if user == nil {
		return nil, errors.New(responseErrors.ErrUserNotFound)
	}

	return user, nil
}

// HandleSendActionConfirmation handles sending a confirmation code for sensitive actions (change password/email/phone)
func (h *AuthRoutes) HandleSendActionConfirmation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	userID := r.Context().Value("user_id")
	if userID == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "user not authenticated", nil)
		return
	}
	var req struct {
		Method string `json:"method"` // "email" or "sms"
		Action string `json:"action"` // e.g. "change-password", "change-email", "change-phone"
		Resend bool   `json:"resend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if req.Method != "email" && req.Method != "sms" {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid confirmation method", nil)
		return
	}
	if req.Action == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "action is required", nil)
		return
	}
	// Generate code
	code, err := h.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate code", err)
		return
	}
	hashedCode, err := h.Auth.TokenManager.HashToken(code)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash code", err)
		return
	}
	// Save code as action confirmation token
	expiry := 10 * time.Minute
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), userID.(string), hashedCode, models.ActionConfirmationToken, expiry); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save confirmation code", err)
		return
	}
	// Send code via email or SMS
	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID.(string))
	if err != nil || user == nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "user not found", err)
		return
	}
	if req.Method == "email" {
		// TODO: Use your email sender to send code
		// h.Auth.EmailSender.SendActionConfirmation(user.Email, code, req.Action)
	} else if req.Method == "sms" && user.PhoneNumber != nil {
		// TODO: Use your SMS sender to send code
		// h.Auth.SMSSender.SendActionConfirmation(*user.PhoneNumber, code, req.Action)
	}
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "confirmation code sent"})
}

// HandleVerifyActionConfirmation verifies the confirmation code for a sensitive action
func (h *AuthRoutes) HandleVerifyActionConfirmation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	userID := r.Context().Value("user_id")
	if userID == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "user not authenticated", nil)
		return
	}
	var req struct {
		Action string `json:"action"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if req.Action == "" || req.Code == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "action and code are required", nil)
		return
	}
	// Get token from DB
	token, err := h.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(r.Context(), userID.(string), models.ActionConfirmationToken)
	if err != nil || token == nil {
		utils.RespondWithError(w, http.StatusBadRequest, "confirmation code not found", err)
		return
	}
	// Compare code
	if err := h.Auth.TokenManager.ValidateHashedToken(token.TokenValue, req.Code); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid confirmation code", err)
		return
	}
	// Mark as used
	if err := h.Auth.Repository.GetTokenRepository().RevokeToken(r.Context(), token.ID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to mark code as used", err)
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "action confirmed"})
}
