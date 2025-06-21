package middleware

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/types"
)

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (for clients behind proxy)
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// Take the first IP if multiple are present
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}
	// Try X-Real-IP header next
	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	parsedIP := net.ParseIP(host)

	if parsedIP != nil {
		if parsedIP.IsLoopback() {
			return "127.0.0.1"
		}
		return parsedIP.String()
	}
	return "unknown"
}

// RateLimiterMiddleware applies rate limiting to HTTP requests
func RateLimiterMiddleware(limiter types.RateLimiter, config *types.RateLimiterConfig, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if limiter is nil or rate limiting is disabled
		if limiter == nil {
			log.Println("Rate limiting disabled or limiter is nil")
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)
		if clientIP == "unknown" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to get client IP",
			})
			return
		}
		// TODO: in future add or get some kind of user info to protect public ip not being treated as single user
		key := "route:" + route + ":ip:" + clientIP
		// Find route specific config
		routeConfig := config.Routes[route]
		// Check rate limit
		if !limiter.Allow(key, routeConfig) {
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
