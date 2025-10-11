package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *CoreHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Parse request
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	// 2. Validate request
	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// 3. Emit BEFORE login event (custom rate limiting, fraud detection, etc)
	loginData := map[string]interface{}{
		"email":              req.Email,
		"username":           req.Username,
		"ip_address":         r.RemoteAddr,
		"user_agent":         r.UserAgent(),
		"timestamp":          time.Now().Format("2006-01-02 15:04:05"),
		"user_id":            r.Context().Value(types.UserIDKey),
		"method":             r.Method,
		"uri":                r.RequestURI,
		"protocol":           r.Proto,
		"host":               r.Host,
		"referer":            r.Referer(),
		"forwarded_for":      r.Header.Get("X-Forwarded-For"),
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"),
	}
	if err := h.deps.Events.EmitSync(ctx, "before:login", loginData); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Login blocked: "+err.Error())
		return
	}

	// 4. Call service - ALL business logic here
	response, err := h.CoreService.Login(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	accessTokenName := "goauth_access_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    response.Token,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure, // Set to false in development
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge, // 24 hours
	})
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    response.RefreshToken,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure, // Set to false in development
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge, // 24 hours
	})

	// 6. Return success response
	http_utils.RespondSuccess(w, response, nil)
}
