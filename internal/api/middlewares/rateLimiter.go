package middlewares

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

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
		if !limiter.Allow(r.Context(), key, routeConfig.WindowSize, routeConfig.MaxRequests, routeConfig.BlockDuration) {
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
		if !limiter.Allow(r.Context(), key, routeConfig.WindowSize, routeConfig.MaxRequests, routeConfig.BlockDuration) {
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
