package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Parse request
	var req dto.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// 2. Validate request
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// 3. Emit BEFORE signup event (rate limiting, fraud detection, etc)
	signupData := map[string]interface{}{
		// User-provided identifiers
		"email":    req.Email,
		"username": req.Username,
		"phone":    req.PhoneNumber,

		// Network info
		"ip_address":    r.RemoteAddr,                    // primary IP
		"forwarded_for": r.Header.Get("X-Forwarded-For"), // if behind proxy
		"user_agent":    r.UserAgent(),                   // browser/device info
		"referer":       r.Referer(),                     // where the request came from
		"host":          r.Host,                          // target host

		// Request info
		"method":    r.Method,     // GET, POST, etc.
		"uri":       r.RequestURI, // path + query
		"protocol":  r.Proto,      // HTTP/1.1, HTTP/2
		"timestamp": time.Now(),   // when request occurred

		// Optional: session/user context
		"user_id":    r.Context().Value(types.UserIDKey), // if logged in
		"request_id": r.Header.Get("X-Request-ID"),       // unique request id

		// Optional: device fingerprint (frontend can send)
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"), // e.g., hash of browser + screen + timezone
	}

	if err := h.deps.Events.EmitSync(ctx, types.EventBeforeSignup, signupData); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Signup blocked: "+err.Error())
		return
	}

	response, err := h.CoreService.Signup(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}
	h.deps.Events.EmitAsync(ctx, types.EventAfterSignup, map[string]interface{}{
		"request_info":          signupData,
		"user":                  response.User,
		"verification_required": h.deps.Config.Core.RequireEmailVerification || h.deps.Config.Core.RequirePhoneVerification,
	})

	w.WriteHeader(http.StatusCreated)
	http_utils.RespondSuccess(w, response, nil)
}
