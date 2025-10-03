package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and validate request
	var req dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Emit BEFORE signup event (validation, checks, etc)
	signupData := map[string]interface{}{
		"email":    req.Email,
		"username": req.Username,
		"phone":    req.Phone,
	}
	if err := h.deps.Events.EmitSync(ctx, "before:signup", signupData); err != nil {
		h.jsonError(w, "Signup blocked: "+err.Error(), http.StatusForbidden)
		return
	}

	// TODO: Implement full signup logic
	// 1. Check if user already exists
	// 2. Hash password
	// 3. Create user in database
	// 4. Generate session token
	// 5. Create session

	user := map[string]interface{}{
		"id":       "user-123",
		"email":    req.Email,
		"username": req.Username,
		"name":     req.Name,
		"phone":    req.Phone,
	}

	// Emit AFTER signup event (send welcome email, etc)
	h.deps.Events.Emit(ctx, "after:signup", user)

	h.jsonSuccess(w, dto.AuthResponse{
		Token:   "example-token",
		Message: "Signup successful",
		User: &dto.UserDTO{
			ID:       "user-123",
			Email:    req.Email,
			Username: req.Username,
			Name:     req.Name,
			Phone:    req.Phone,
			Active:   true,
		},
	})
}
