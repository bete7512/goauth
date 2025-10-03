package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

// CheckAvailability handles POST /check-availability
func (h *CoreHandler) CheckAvailability(w http.ResponseWriter, r *http.Request) {
	// ctx := r.Context()

	var req dto.CheckAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Implement check availability logic
	// Check each field that was provided

	if req.Email != "" {
		// Check email availability
		// available, err := h.CoreService.CheckAvailability(ctx, "email", req.Email)
		h.jsonSuccess(w, dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "email",
			Message:   "Email is available",
		})
		return
	}

	if req.Username != "" {
		// Check username availability
		h.jsonSuccess(w, dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "username",
			Message:   "Username is available",
		})
		return
	}

	if req.Phone != "" {
		// Check phone availability
		h.jsonSuccess(w, dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "phone",
			Message:   "Phone number is available",
		})
		return
	}

	h.jsonError(w, "No field provided to check", http.StatusBadRequest)
}

// ResendVerificationEmail handles POST /resend-verification-email
func (h *CoreHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	// Reuse the same logic as SendVerificationEmail
	h.SendVerificationEmail(w, r)
}

// ResendVerificationPhone handles POST /resend-verification-phone
func (h *CoreHandler) ResendVerificationPhone(w http.ResponseWriter, r *http.Request) {
	// Reuse the same logic as SendVerificationPhone
	h.SendVerificationPhone(w, r)
}
