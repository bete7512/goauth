package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

// SendVerificationEmail handles POST /send-verification-email
func (h *CoreHandler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement send verification email logic
	// 1. Check if user exists
	// 2. Generate verification token
	// 3. Store token in database
	// 4. Emit event for notification module to send email

	h.deps.Events.Emit(ctx, "email:verification:sent", map[string]interface{}{
		"email":             req.Email,
		"verification_link": "https://app.com/verify?token=xxx",
		"code":              "123456",
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Verification email sent successfully",
		Success: true,
	})
}

// VerifyEmail handles POST /verify-email
func (h *CoreHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement verify email logic
	// 1. Find token in database
	// 2. Check if valid and not expired
	// 3. Mark user email as verified
	// 4. Mark token as used
	// 5. Emit event

	h.deps.Events.Emit(ctx, "email:verified", map[string]interface{}{
		"email": req.Email,
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Email verified successfully",
		Success: true,
	})
}

// SendVerificationPhone handles POST /send-verification-phone
func (h *CoreHandler) SendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.SendVerificationPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement send verification phone logic
	// 1. Check if user exists
	// 2. Generate 6-digit OTP code
	// 3. Store code in database
	// 4. Emit event for notification module to send SMS

	h.deps.Events.Emit(ctx, "phone:verification:sent", map[string]interface{}{
		"phone": req.Phone,
		"code":  "123456",
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Verification code sent to your phone",
		Success: true,
	})
}

// VerifyPhone handles POST /verify-phone
func (h *CoreHandler) VerifyPhone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.VerifyPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement verify phone logic
	// 1. Find code in database
	// 2. Check if valid and not expired
	// 3. Mark user phone as verified
	// 4. Mark code as used
	// 5. Emit event

	h.deps.Events.Emit(ctx, "phone:verified", map[string]interface{}{
		"phone": req.Phone,
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Phone verified successfully",
		Success: true,
	})
}
