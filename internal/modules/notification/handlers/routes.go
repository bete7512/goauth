package handlers

import (
	"encoding/json"
	"net/http"

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

// VerifyEmail handles POST /verify-email
func (h *NotificationHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req dto.VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	// Call notification service to verify email
	verification, err := h.NotificationService.VerifyEmail(ctx, req.Token)
	if err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "VERIFICATION_ERROR", err.Error())
		return
	}

	response := map[string]interface{}{
		"message": "Email verified successfully",
		"email":   verification.Email,
		"user_id": verification.UserID,
	}

	http_utils.RespondSuccess(w, response, nil)
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
