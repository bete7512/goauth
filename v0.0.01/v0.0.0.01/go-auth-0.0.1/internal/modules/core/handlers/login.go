package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

func (h *CoreHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse and validate request
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Prepare login data
	loginData := map[string]interface{}{
		"email":      req.Email,
		"username":   req.Username,
		"ip_address": r.RemoteAddr,
		"user_agent": r.UserAgent(),
	}

	// Emit BEFORE login event (rate limiting, fraud detection, etc)
	if err := h.deps.Events.EmitSync(ctx, "before:login", loginData); err != nil {
		h.jsonError(w, "Login blocked: "+err.Error(), http.StatusForbidden)
		return
	}

	// TODO: Implement full login logic
	// 1. Find user by email or username
	// 2. Verify password
	// 3. Check if account is active
	// 4. Check if 2FA is enabled
	// 5. Generate session token
	// 6. Create session

	user := map[string]interface{}{
		"id":       "user-123",
		"email":    req.Email,
		"username": req.Username,
		"name":     "User Name",
	}

	// Emit AFTER login event (analytics, update last login, etc)
	h.deps.Events.Emit(ctx, "after:login", map[string]interface{}{
		"user":       user,
		"ip_address": r.RemoteAddr,
		"timestamp":  time.Now().Format(time.RFC3339),
	})

	h.jsonSuccess(w, dto.AuthResponse{
		Token:   "example-token",
		Message: "Login successful",
		User: &dto.UserDTO{
			ID:       "user-123",
			Email:    req.Email,
			Username: req.Username,
			Name:     "User Name",
			Active:   true,
		},
		ExpiresIn: 86400, // 24 hours
	})
}
