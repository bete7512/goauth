package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
)

func (h *CoreHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Parse request
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Invalid request body")
		return
	}

	// 2. Validate request
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", err.Error())
		return
	}

	// 3. Emit BEFORE login event (rate limiting, fraud detection, etc)
	loginData := map[string]interface{}{
		"email":      req.Email,
		"username":   req.Username,
		"ip_address": r.RemoteAddr,
		"user_agent": r.UserAgent(),
	}
	if err := h.deps.Events.EmitSync(ctx, "before:login", loginData); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, "LOGIN_BLOCKED", "Login blocked: "+err.Error())
		return
	}

	// 4. Call service - ALL business logic here
	response, err := h.CoreService.Login(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// TODO: add to set cool
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
	http_utils.RespondSuccess(w, response, nil)
}
