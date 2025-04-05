package middleware

import (
	"encoding/json"
	"log"
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

    // Fall back to RemoteAddr
    ip := strings.Split(r.RemoteAddr, ":")[0]
    if strings.Split(strings.Split(r.RemoteAddr, "]")[0],"[")[1] == "::1" {
        return "127.0.0.1"
    }
    
    return ip
}

// RateLimiterMiddleware applies rate limiting to HTTP requests
func RateLimiterMiddleware(limiter types.RateLimiter, config types.RateLimiterConfig, route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting if limiter is nil or rate limiting is disabled
		if limiter == nil {
			log.Println("Rate limiting disabled or limiter is nil")
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)
		key := "route:" + route + ":ip:" + clientIP

		// Find route specific config
		routeConfig := config.Routes[route]

		// Check rate limit
		if !limiter.Allow(key, routeConfig) {
			log.Printf("Rate limit exceeded for '%s'", key)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", routeConfig.BlockDuration.String())
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":      "Rate limit exceeded. Please try again later.",
				"retryAfter": routeConfig.BlockDuration.String(),
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}

// BruteForceProtectionMiddleware specifically handles brute force protection for authentication
func BruteForceProtectionMiddleware(limiter types.RateLimiter, config types.BruteForceConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if limiter == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Extract username from request (adjust according to your authentication flow)
		err := r.ParseForm()
		if err != nil {
			log.Printf("Error parsing form: %v", err)
		}

		username := r.FormValue("username")
		clientIP := getClientIP(r)

		var identifier string
		if config.TrackByCombined {
			identifier = "combined:" + username + ":" + clientIP
		} else if config.TrackByUsername && username != "" {
			identifier = "username:" + username
		} else if config.TrackByIP {
			identifier = "ip:" + clientIP
		} else {
			// Default to IP if no tracking method specified
			identifier = "ip:" + clientIP
		}

		log.Printf("Brute force protection check for identifier: %s", identifier)

		if !limiter.BruteForceProtection(identifier, config) {
			log.Printf("Brute force protection triggered for: %s", identifier)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Too many failed attempts. Please try again later.",
			})
			return
		}

		next.ServeHTTP(w, r)
	}
}
