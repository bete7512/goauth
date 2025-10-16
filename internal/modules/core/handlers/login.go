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

	var req dto.LoginRequest
	metadata := map[string]interface{}{
		"ip_address":         r.RemoteAddr,                         // primary IP
		"forwarded_for":      r.Header.Get("X-Forwarded-For"),      // if behind proxy
		"user_agent":         r.UserAgent(),                        // browser/device info
		"referer":            r.Referer(),                          // where the request came from
		"host":               r.Host,                               // target host
		"timestamp":          time.Now(),                           // when request occurred
		"user_id":            r.Context().Value(types.UserIDKey),   // if logged in
		"request_id":         r.Header.Get("X-Request-ID"),         // unique request id
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"), // e.g., hash of browser + screen + timezone
		"headers":            r.Header,                             // all headers
		"cookies":            r.Cookies(),                          // all cookies
		"query_params":       r.URL.Query(),                        // all query params
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	loginData := map[string]interface{}{
		"body":     req,
		"metadata": metadata,
	}
	if err := h.deps.Events.EmitSync(ctx, "before:login", loginData); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Login blocked: "+err.Error())
		return
	}

	response, err := h.CoreService.Login(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}
	if response.AccessToken == nil || response.RefreshToken == nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate tokens")
		return
	}
	h.setSessionCookies(w, response)
	if err := h.deps.Events.EmitAsync(ctx, types.EventAfterLogin, map[string]interface{}{
		"user":     *response.User.ToUser(), // Dereference pointer to value
		"session":  *response,
		"metadata": metadata,
	}); err != nil {
		return
	}
	http_utils.RespondSuccess(w, response, nil)
}

func (h *CoreHandler) setSessionCookies(w http.ResponseWriter, response *dto.AuthResponse) {
	if response.AccessToken == nil || response.RefreshToken == nil {
		return
	}
	accessTokenName := "goauth_access_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    *response.AccessToken,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure, // Set to false in development
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge, // 24 hours
	})
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    *response.RefreshToken,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure, // Set to false in development
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge, // 24 hours
	})
}
