package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *StatelessHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()


	var req dto.LoginRequest
	metadata := map[string]interface{}{
		"ip_address":         r.RemoteAddr,
		"forwarded_for":      r.Header.Get("X-Forwarded-For"),
		"user_agent":         r.UserAgent(),
		"referer":            r.Referer(),
		"host":               r.Host,
		"timestamp":          time.Now(),
		"user_id":            r.Context().Value(types.UserIDKey),
		"request_id":         r.Header.Get("X-Request-ID"),
		"device_fingerprint": r.Header.Get("X-Device-Fingerprint"),
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

	response, err := h.StatelessService.Login(ctx, &req)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	if response.AccessToken == nil || response.RefreshToken == nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate tokens")
		return
	}

	// Set cookies for convenience (clients can also use Bearer tokens)
	h.setTokenCookies(w, &response)

	if emitErr := h.deps.Events.EmitAsync(ctx, types.EventAfterLogin, map[string]interface{}{
		"user":     response.User.ToUser(),
		"metadata": metadata,
	}); emitErr != nil {
		h.deps.Logger.Errorf("stateless: failed to emit after login event: %v", emitErr)
	}

	http_utils.RespondSuccess(w, response, nil)
}

func (h *StatelessHandler) setTokenCookies(w http.ResponseWriter, response *dto.AuthResponse) {
	if response.AccessToken == nil || response.RefreshToken == nil {
		return
	}
	accessTokenName := "goauth_access_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    *response.AccessToken,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure,
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge,
	})
	refreshTokenName := "goauth_refresh_" + h.deps.Config.Security.Session.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    *response.RefreshToken,
		HttpOnly: h.deps.Config.Security.Session.HttpOnly,
		Secure:   h.deps.Config.Security.Session.Secure,
		SameSite: h.deps.Config.Security.Session.SameSite,
		Path:     h.deps.Config.Security.Session.Path,
		MaxAge:   h.deps.Config.Security.Session.MaxAge,
	})
}
