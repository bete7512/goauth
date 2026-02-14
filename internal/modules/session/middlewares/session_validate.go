package middlewares

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/session/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// NewSessionValidateMiddleware creates a middleware that validates session existence
// using the signed session cookie (cheap HMAC check) with DB fallback.
//
// Flow:
//  1. Extract session_id from context (set by auth middleware from JWT claims)
//  2. If no session_id → skip (stateless JWT or unauthenticated)
//  3. If sensitive path → always validate from DB
//  4. Try decoding session cookie → if valid + not stale, pass through
//  5. Cookie miss/UpdateAge exceeded → DB fallback → if session gone, reject 401
//  6. On success → refresh the session cookie (keeps cache warm)
func NewSessionValidateMiddleware(
	validator *services.SessionValidator,
	sessionCfg types.SessionConfig,
	log logger.Logger,
) func(http.Handler) http.Handler {
	sessionCookieName := "goauth_session_" + sessionCfg.Name

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only act on authenticated requests with a session_id
			sessionID, ok := r.Context().Value(types.SessionIDKey).(string)
			if !ok || sessionID == "" {
				next.ServeHTTP(w, r) // Not a session-based request, skip
				return
			}

			userID, _ := r.Context().Value(types.UserIDKey).(string)

			// Sensitive paths always check DB
			if validator.IsSensitivePath(r.URL.Path) {
				dbResult := validator.ValidateFromDB(r.Context(), sessionID)
				if !dbResult.Valid {
					http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Session has been revoked")
					return
				}
				if dbResult.ShouldRefresh {
					refreshSessionCookie(w, validator, sessionCookieName, sessionID, dbResult.UserID, sessionCfg, log)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Try session cookie cache first
			cookieValue := ""
			if sessionCookie, err := r.Cookie(sessionCookieName); err == nil {
				cookieValue = sessionCookie.Value
			}

			result := validator.ValidateFromCookie(cookieValue)
			if result.Valid && result.UserID == userID && result.SessionID == sessionID {
				next.ServeHTTP(w, r)
				return
			}

			// Cookie invalid, expired, or UpdateAge exceeded — DB fallback
			dbResult := validator.ValidateFromDB(r.Context(), sessionID)
			if !dbResult.Valid {
				http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "Session has been revoked")
				return
			}

			// Refresh session cookie after successful DB validation
			if dbResult.ShouldRefresh {
				refreshSessionCookie(w, validator, sessionCookieName, sessionID, dbResult.UserID, sessionCfg, log)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func refreshSessionCookie(
	w http.ResponseWriter,
	validator *services.SessionValidator,
	cookieName, sessionID, userID string,
	sessionCfg types.SessionConfig,
	log logger.Logger,
) {
	cookieValue, err := validator.BuildCookieValue(sessionID, userID)
	if err != nil {
		log.Errorf("session: failed to build session cookie: %v", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		HttpOnly: true,
		Secure:   sessionCfg.Secure,
		SameSite: sessionCfg.SameSite,
		Path:     sessionCfg.Path,
		MaxAge:   int(validator.CacheTTL().Seconds()),
	})
}
