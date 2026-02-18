package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *SessionHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.LoginRequest
	metadata := &types.RequestMetadata{
		IPAddress:         r.RemoteAddr,
		ForwardedFor:      r.Header.Get("X-Forwarded-For"),
		UserAgent:         r.UserAgent(),
		Referer:           r.Referer(),
		Host:              r.Host,
		Timestamp:         time.Now(),
		RequestID:         r.Header.Get("X-Request-ID"),
		DeviceFingerprint: r.Header.Get("X-Device-Fingerprint"),
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if err := h.deps.Events.EmitSync(ctx, types.EventBeforeLogin, &types.BeforeHookData{
		Body:     req,
		Metadata: metadata,
	}); err != nil {
		http_utils.RespondError(w, http.StatusForbidden, string(types.ErrForbidden), "Login blocked: "+err.Error())
		return
	}

	response, err := h.service.Login(ctx, &req, metadata)
	if err != nil {
		http_utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	h.setSessionCookies(w, &response)

	if err := h.deps.Events.EmitAsync(ctx, types.EventAfterLogin, &types.LoginEventData{
		User:     response.User.ToUser(),
		Session:  response,
		Metadata: metadata,
	}); err != nil {
		h.deps.Logger.Errorf("session: failed to emit after login event: %v", err)
	}

	// Emit audit event for login success
	if err := h.deps.Events.EmitAsync(ctx, types.EventAuthLoginSuccess, map[string]interface{}{
		"actor_id":   response.User.ID,
		"user_id":    response.User.ID,
		"ip":         metadata.IPAddress,
		"user_agent": metadata.UserAgent,
		"details":    "User logged in successfully",
	}); err != nil {
		h.deps.Logger.Errorf("session: failed to emit audit login event: %v", err)
	}

	http_utils.RespondSuccess(w, response, nil)
}

func (h *SessionHandler) setSessionCookies(w http.ResponseWriter, response *dto.AuthResponse) {

	sessionCfg := h.deps.Config.Security.Session

	accessTokenName := "goauth_access_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     accessTokenName,
		Value:    response.AccessToken,
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   sessionCfg.MaxAge,
	})
	refreshTokenName := "goauth_refresh_" + sessionCfg.Name
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenName,
		Value:    response.RefreshToken,
		HttpOnly: sessionCfg.HttpOnly,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   sessionCfg.MaxAge,
	})

	// Set session cache cookie when cookie_cache strategy is enabled
	if h.encoder != nil && response.SessionID != "" && response.User != nil {
		h.setSessionCacheCookie(w, response.SessionID, response.User.ID)
	}
}

func (h *SessionHandler) setSessionCacheCookie(w http.ResponseWriter, sessionID, userID string) {
	sessionCfg := h.deps.Config.Security.Session
	cacheTTL := h.sessionModuleCacheTTL()

	cookieValue, err := h.encoder.Encode(&types.SessionCookieData{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(cacheTTL).Unix(),
		IssuedAt:  time.Now().Unix(),
	})
	if err != nil {
		h.deps.Logger.Errorf("session: failed to encode session cookie: %v", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "goauth_session_" + sessionCfg.Name,
		Value:    cookieValue,
		HttpOnly: true,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   int(cacheTTL.Seconds()),
	})
}

// sessionModuleCacheTTL reads CookieCacheTTL from the SessionModuleConfig passed via deps.Options.
func (h *SessionHandler) sessionModuleCacheTTL() time.Duration {
	if cfg, ok := h.deps.Options.(*config.SessionModuleConfig); ok && cfg.CookieCacheTTL > 0 {
		return cfg.CookieCacheTTL
	}
	return 5 * time.Minute // default fallback
}
