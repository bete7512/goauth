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

	// 4. Call service - ALL business logic here
	response, err := h.CoreService.Signup(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}
	// 5. Emit after:signup event (include verification context)
	h.deps.Events.EmitAsync(ctx, types.EventAfterSignup, map[string]interface{}{
		"request_info":          signupData,
		"user_id":               response.User.ID,
		"email":                 response.User.Email,
		"name":                  response.User.Name,
		"username":              response.User.Username,
		"first_name":            response.User.FirstName,
		"last_name":             response.User.LastName,
		"phone_number":          response.User.PhoneNumber,
		"extended_attributes":   response.User.ExtendedAttributes,
		"email_verified":        response.User.EmailVerified,
		"phone_verified":        response.User.PhoneNumberVerified,
		"verification_required": h.deps.Config.Core.RequireEmailVerification || h.deps.Config.Core.RequirePhoneVerification,
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
	http_utils.RespondSuccess(w, response, nil)
}
