package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type Middleware struct {
	Auth *config.Auth
}

func NewMiddleware(auth *config.Auth) *Middleware {
	return &Middleware{
		Auth: auth,
	}
}

// RateLimiterMiddleware applies rate limiting to HTTP requests
func (m *Middleware) RateLimiterMiddleware(limiter interfaces.RateLimiter, config *config.RateLimiterConfig, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if limiter is nil or rate limiting is disabled
		if limiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := utils.GetIpFromRequest(r)
		if clientIP == "unknown" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to get client IP",
			})
			return
		}

		key := "route:" + route + ":ip:" + clientIP

		// Try to get user ID, but don't fail if we can't - just use IP-based limiting
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err == nil && userID != "" {
			// User is authenticated, use user-based rate limiting
			key = "route:" + route + ":user:" + userID + ":ip:" + clientIP
		} else {
			// User is not authenticated, use IP + User-Agent based rate limiting
			userAgent := r.Header.Get("User-Agent")
			if userAgent != "" {
				key = "route:" + route + ":user_agent:" + userAgent + ":ip:" + clientIP
			}
		}

		routeConfig := config.Routes[route]
		if !limiter.Allow(key, routeConfig.WindowSize, routeConfig.MaxRequests, routeConfig.BlockDuration) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", routeConfig.BlockDuration.String())
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":       "Rate limit exceeded. Please try again later.",
				"retry_after": routeConfig.BlockDuration.String(),
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}

// TODO: make a research before applying this middleware
// GlobalRateLimiterMiddleware is a middleware that applies to all routes
func (m *Middleware) GlobalRateLimiterMiddleware(limiter interfaces.RateLimiter, config *config.RateLimiterConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := utils.GetIpFromRequest(r)
		if clientIP == "unknown" {
			utils.RespondWithError(w, http.StatusBadRequest, "failed to get client ip", errors.New("failed to get client ip"))
			return
		}

		key := "global:ip:" + clientIP

		// Try to get user ID, but don't fail if we can't - just use IP-based limiting
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err == nil && userID != "" {
			// User is authenticated, use user-based rate limiting
			key = "global:user:" + userID + ":ip:" + clientIP
		} else {
			// User is not authenticated, use IP + User-Agent based rate limiting
			userAgent := r.Header.Get("User-Agent")
			if userAgent != "" {
				key = "global:user_agent:" + userAgent + ":ip:" + clientIP
			}
		}

		routeConfig := config.Routes["global"]
		if !limiter.Allow(key, routeConfig.WindowSize, routeConfig.MaxRequests, routeConfig.BlockDuration) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", routeConfig.BlockDuration.String())
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":       "Rate limit exceeded. Please try again later.",
				"retry_after": routeConfig.BlockDuration.String(),
			})
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (m *Middleware) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if userID == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user id not found in request"))
			return
		}
		user, err := m.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if user == nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user not found"))
			return
		}
		if user.IsAdmin == nil || !*user.IsAdmin {
			utils.RespondWithError(w, http.StatusForbidden, "forbidden", errors.New("user is not an admin"))
			return
		}
		ctx := context.WithValue(r.Context(), config.UserIDKey, userID)
		ctx = context.WithValue(ctx, config.IsAdminKey, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// AuthMiddleware validates user authentication but doesn't require admin privileges
func (m *Middleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := m.getUserIdFromRequest(r, m.Auth.Config.AuthConfig.Cookie.Name)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", err)
			return
		}
		if userID == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "unauthorized", errors.New("user id not found in request"))
			return
		}

		log.Println("userID?>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", userID)
		// Add user ID to context for downstream handlers
		ctx := context.WithValue(r.Context(), config.UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// getUserIdFromRequest extracts and validates the token from a request
func (m *Middleware) getUserIdFromRequest(r *http.Request, cookieName string) (string, error) {
	token := m.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := m.Auth.TokenManager.ValidateJWTToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (m *Middleware) extractToken(r *http.Request, cookieName string) string {
	switch m.Auth.Config.AuthConfig.Methods.Type {
	case config.AuthenticationTypeCookie:
		cookie, err := r.Cookie("___goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	case config.AuthenticationTypeBearer:
		bearerToken := r.Header.Get("Authorization")
		if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
			return bearerToken[7:]
		}
	}
	return ""
}
