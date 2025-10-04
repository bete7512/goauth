package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Parse request
	var req dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 2. Validate request
	if err := req.Validate(); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Emit BEFORE signup event (rate limiting, fraud detection, etc)
	signupData := map[string]interface{}{
		"email":      req.Email,
		"username":   req.Username,
		"phone":      req.Phone,
		"ip_address": r.RemoteAddr,
	}
	if err := h.deps.Events.EmitSync(ctx, "before:signup", signupData); err != nil {
		h.jsonError(w, "Signup blocked: "+err.Error(), http.StatusForbidden)
		return
	}

	// 4. Call service - ALL business logic here
	response, err := h.CoreService.Signup(ctx, &req)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 5. Emit after:signup event
	h.deps.Events.Emit(ctx, "after:signup", map[string]interface{}{
		"user_id": response.User.ID,
		"email":   response.User.Email,
	})

	// 5. Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    response.Token,
		HttpOnly: true,
		Secure:   true, // Set to false in development
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400, // 24 hours
	})

	// 6. Return success response
	w.WriteHeader(http.StatusCreated)
	h.jsonSuccess(w, response)
}
