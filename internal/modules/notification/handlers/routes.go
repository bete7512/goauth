package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/bete7512/goauth/internal/modules/notification/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// SendVerificationEmail handles POST /send-verification-email
func (h *NotificationHandler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Send verification email directly
	err := h.NotificationService.SendEmailVerification(ctx, req.Email)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to send verification email")
		return
	}

	response := map[string]interface{}{
		"message": "Verification email sent successfully",
		"email":   req.Email,
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ResendVerificationEmail handles POST /resend-verification-email
func (h *NotificationHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req dto.SendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	err := h.NotificationService.ResendEmailVerification(ctx, req.Email)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to resend verification email")
		return
	}

	response := map[string]interface{}{
		"message": "Verification email resent successfully",
		"email":   req.Email,
	}

	http_utils.RespondSuccess(w, response, nil)
}

// SendVerificationPhone handles POST /send-verification-phone
func (h *NotificationHandler) SendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Send verification SMS directly
	err := h.NotificationService.SendPhoneVerification(ctx, req.PhoneNumber)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to send verification SMS")
		return
	}

	response := map[string]interface{}{
		"message":      "Verification SMS sent successfully",
		"phone_number": req.PhoneNumber,
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ResendVerificationPhone handles POST /resend-verification-phone
func (h *NotificationHandler) ResendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req dto.SendVerificationPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	err := h.NotificationService.ResendPhoneVerification(ctx, req.PhoneNumber)
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to resend verification SMS")
		return
	}

	response := map[string]interface{}{
		"message":      "Verification SMS resent successfully",
		"phone_number": req.PhoneNumber,
	}

	http_utils.RespondSuccess(w, response, nil)
}

// ForgotPassword handles POST /forgot-password
func (h *NotificationHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	if req.Email != "" {
		err := h.NotificationService.SendPasswordResetEmail(ctx, req.Email)
		if err != nil {
			http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to send password reset notification")
			return
		}
	}
	if req.Phone != "" {
		err := h.NotificationService.SendPasswordResetSMS(ctx, req.Phone)
		if err != nil {
			http_utils.RespondError(w, http.StatusInternalServerError, "NOTIFICATION_ERROR", "Failed to send password reset notification")
			return
		}
	}

	response := map[string]interface{}{
		"message": "Password reset instructions sent successfully",
	}

	http_utils.RespondSuccess(w, response, nil)
}

// VerifyEmail handles GET /verify-email?token=xxx
func (h *NotificationHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract token from query parameter
	token := r.URL.Query().Get("token")
	if token == "" {
		// Redirect to frontend with error
		h.redirectToFrontend(w, r, false, "Missing verification token")
		return
	}

	// Call notification service to verify email
	_, err := h.NotificationService.VerifyEmail(ctx, token)
	if err != nil {
		// Redirect to frontend with error
		h.redirectToFrontend(w, r, false, err.Error())
		return
	}

	// Redirect to frontend with success
	h.redirectToFrontend(w, r, true, "Email verified successfully")
}

// redirectToFrontend redirects to the frontend verify email page
func (h *NotificationHandler) redirectToFrontend(w http.ResponseWriter, r *http.Request, success bool, message string) {
	// Get frontend config
	frontendConfig := h.deps.Config.FrontendConfig
	if frontendConfig == nil {
		// Fallback to JSON response if frontend config is not set
		if success {
			http_utils.RespondSuccess(w, map[string]interface{}{
				"message": message,
			}, nil)
		} else {
			http_utils.RespondError(w, http.StatusBadRequest, "VERIFICATION_ERROR", message)
		}
		return
	}

	// Build redirect URL with properly encoded query parameters
	redirectURL := frontendConfig.URL + frontendConfig.VerifyEmailCallbackPath

	// Add query parameters for status and message
	params := url.Values{}
	if success {
		params.Add("status", "success")
	} else {
		params.Add("status", "error")
	}

	redirectURL += "?" + params.Encode()

	// Perform redirect
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// VerifyPhone handles POST /verify-phone
func (h *NotificationHandler) VerifyPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.VerifyPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Call notification service to verify phone
	verification, err := h.NotificationService.VerifyPhone(ctx, req.Code, req.PhoneNumber)
	if err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "VERIFICATION_ERROR", err.Error())
		return
	}

	response := map[string]interface{}{
		"message":      "Phone verified successfully",
		"phone_number": verification.PhoneNumber,
		"user_id":      verification.UserID,
	}

	http_utils.RespondSuccess(w, response, nil)
}
