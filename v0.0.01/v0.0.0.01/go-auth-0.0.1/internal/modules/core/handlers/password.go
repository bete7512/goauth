package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

// ForgotPassword handles POST /forgot-password
func (h *CoreHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement forgot password logic
	// 1. Find user by email or phone
	// 2. Generate reset token/code
	// 3. Store in database
	// 4. Emit event for notification module

	h.deps.Events.Emit(ctx, "password:reset:request", map[string]interface{}{
		"email":        req.Email,
		"phone":        req.Phone,
		"reset_link":   "https://app.com/reset?token=xxx",
		"code":         "123456",
		"phone_number": req.Phone,
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Password reset instructions sent",
		Success: true,
	})
}

// ResetPassword handles POST /reset-password
func (h *CoreHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement reset password logic
	// 1. Verify token/code
	// 2. Find user
	// 3. Hash new password
	// 4. Update user password
	// 5. Mark token as used
	// 6. Emit event

	h.deps.Events.Emit(ctx, "password:reset", map[string]interface{}{
		"email": req.Email,
		"phone": req.Phone,
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Password reset successfully",
		Success: true,
	})
}

// ChangePassword handles PUT /change-password
func (h *CoreHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: Get user ID from context (set by auth middleware)
	// userID := ctx.Value("user_id").(string)

	var req dto.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement change password logic
	// 1. Get user from database
	// 2. Verify old password
	// 3. Hash new password
	// 4. Update user password
	// 5. Emit event

	h.deps.Events.Emit(ctx, "password:changed", map[string]interface{}{
		"email": "user@example.com",
		"name":  "User Name",
	})

	h.jsonSuccess(w, dto.MessageResponse{
		Message: "Password changed successfully",
		Success: true,
	})
}
