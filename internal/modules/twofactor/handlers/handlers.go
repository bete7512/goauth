package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/twofactor/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

type TwoFactorHandler struct {
	deps    config.ModuleDependencies
	service services.TwoFactorService
}

func NewTwoFactorHandler(deps config.ModuleDependencies, service services.TwoFactorService) *TwoFactorHandler {
	return &TwoFactorHandler{
		deps:    deps,
		service: service,
	}
}

// getUserID extracts user ID from request context
func getUserID(r *http.Request) (string, *types.GoAuthError) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		return "", types.NewUnauthorizedError()
	}
	return userID, nil
}

// SetupHandler initiates 2FA setup - generates secret, QR code, and backup codes
func (h *TwoFactorHandler) SetupHandler(w http.ResponseWriter, r *http.Request) {
	userID, authErr := getUserID(r)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Check if 2FA is already enabled
	existing, _ := h.service.GetTwoFactorConfig(r.Context(), userID)
	if existing != nil && existing.Enabled {
		authErr := types.NewTwoFactorAlreadyEnabledError()
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// If there's a pending (unverified) setup, clean it up before starting fresh.
	// Without this, repeated setup calls silently overwrite the secret while the
	// authenticator app still holds the old one — causing permanent TOTP mismatch.
	if existing != nil && !existing.Enabled {
		if authErr := h.service.DisableTwoFactor(r.Context(), userID); authErr != nil {
			http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
			return
		}
	}

	// Fetch user email for QR code
	user, authErr := h.service.GetUser(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Generate secret and QR URL
	secret, qrURL, authErr := h.service.GenerateSecret(r.Context(), user.Email)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Generate backup codes
	backupCodes, authErr := h.service.GenerateBackupCodes(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Save 2FA config (enabled=false, verified=false until user verifies first code)
	tfConfig := &models.TwoFactor{
		UserID:   userID,
		Secret:   secret,
		Enabled:  false,
		Verified: false,
		Method:   "totp",
	}
	if authErr := h.service.SaveTwoFactorConfig(r.Context(), tfConfig); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Save backup codes to database
	if authErr := h.service.SaveBackupCodes(r.Context(), userID, backupCodes); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Return setup data
	http_utils.RespondSuccess(w, map[string]any{
		"secret":       secret,
		"qr_url":       qrURL,
		"backup_codes": backupCodes,
		"message":      "Scan the QR code with your authenticator app, then verify with a code to enable 2FA",
	}, nil)
}

// VerifyHandler verifies TOTP code and enables 2FA
func (h *TwoFactorHandler) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	userID, authErr := getUserID(r)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		authErr := types.NewValidationError("Invalid request body")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	if req.Code == "" {
		authErr := types.NewValidationError("Code is required")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Get 2FA config (checks against non-enabled config)
	tfConfig, authErr := h.service.GetTwoFactorConfig(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Manually verify code against secret (even if not enabled yet)
	if authErr := h.service.VerifyCodeManual(r.Context(), tfConfig.Secret, req.Code); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Enable 2FA
	if authErr := h.service.EnableTwoFactor(r.Context(), userID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Emit event
	_ = h.deps.Events.EmitAsync(r.Context(), types.EventAuth2FAEnabled, &types.TwoFactorEventData{UserID: userID})

	http_utils.RespondSuccess(w, map[string]string{
		"message": "Two-factor authentication enabled successfully",
	}, nil)
}

// DisableHandler disables 2FA (requires current TOTP code for verification)
func (h *TwoFactorHandler) DisableHandler(w http.ResponseWriter, r *http.Request) {
	userID, authErr := getUserID(r)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	var req struct {
		Code string `json:"code"` // Current TOTP code for verification
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		authErr := types.NewValidationError("Invalid request body")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	if req.Code == "" {
		authErr := types.NewValidationError("Code is required to disable 2FA")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Verify current TOTP code before allowing disable
	if authErr := h.service.VerifyCode(r.Context(), userID, req.Code); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Delete 2FA config and backup codes
	if authErr := h.service.DisableTwoFactor(r.Context(), userID); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Emit event
	_ = h.deps.Events.EmitAsync(r.Context(), types.EventAuth2FADisabled, &types.TwoFactorEventData{UserID: userID})

	http_utils.RespondSuccess(w, map[string]string{
		"message": "Two-factor authentication disabled successfully",
	}, nil)
}

// StatusHandler returns whether 2FA is enabled for the current user
func (h *TwoFactorHandler) StatusHandler(w http.ResponseWriter, r *http.Request) {
	userID, authErr := getUserID(r)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	tfConfig, _ := h.service.GetTwoFactorConfig(r.Context(), userID)
	enabled := tfConfig != nil && tfConfig.Enabled
	method := ""
	if enabled {
		method = tfConfig.Method
	}

	http_utils.RespondSuccess(w, map[string]any{
		"enabled": enabled,
		"method":  method,
	}, nil)
}

// VerifyLoginHandler verifies 2FA code during login flow
func (h *TwoFactorHandler) VerifyLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TempToken string `json:"temp_token,omitempty"` // Preferred - from 2FA challenge
		UserID    string `json:"user_id,omitempty"`    // Fallback for backward compat
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		authErr := types.NewValidationError("Invalid request body")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	if req.Code == "" {
		authErr := types.NewValidationError("code is required")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Extract user ID from temp token or use provided user_id
	userID := req.UserID
	if req.TempToken != "" {
		extractedUserID, authErr := h.verifyTempToken(req.TempToken)
		if authErr != nil {
			http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
			return
		}
		userID = extractedUserID
	}

	if userID == "" {
		authErr := types.NewValidationError("temp_token or user_id is required")
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Verify TOTP code or backup code
	if authErr := h.service.VerifyCodeOrBackup(r.Context(), userID, req.Code); authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Fetch user
	user, authErr := h.service.GetUser(r.Context(), userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Emit event: 2FA verification successful
	metadata := &types.RequestMetadata{
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	_ = h.deps.Events.EmitAsync(r.Context(), types.EventAuth2FAVerified, &types.Auth2FAVerifiedEventData{
		User:     user,
		Metadata: metadata,
	})

	// Issue tokens - service handles all repository access
	response, authErr := h.service.IssueAuthTokenAfter2FA(r.Context(), user, metadata)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, response, nil)
}

// verifyTempToken verifies and extracts user ID from temporary 2FA token
func (h *TwoFactorHandler) verifyTempToken(tokenString string) (string, *types.GoAuthError) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.deps.Config.Security.JwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return "", types.NewInvalidTokenError()
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", types.NewInvalidTokenError()
	}

	// Verify token type
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "2fa_pending" {
		return "", types.NewInvalidTokenError()
	}

	// Extract user ID
	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" {
		return "", types.NewInvalidTokenError()
	}

	return userID, nil
}
