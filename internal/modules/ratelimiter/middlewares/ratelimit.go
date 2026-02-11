package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/ratelimiter/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// IdentifierStrategy defines how to identify clients for rate limiting
type IdentifierStrategy func(*http.Request) string

// NewRateLimitMiddleware creates a rate limiting middleware
func NewRateLimitMiddleware(service *services.RateLimiterService) func(http.Handler) http.Handler {
	return NewRateLimitMiddlewareWithStrategy(service, IPStrategy)
}

// NewRateLimitMiddlewareWithStrategy creates a rate limiting middleware with custom identification
func NewRateLimitMiddlewareWithStrategy(service *services.RateLimiterService, strategy IdentifierStrategy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client identifier using strategy
			identifier := strategy(r)

			// Check rate limit
			result := service.Check(identifier)

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", result.Limit)
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", result.RetryAfter))
				http_utils.RespondError(w, http.StatusTooManyRequests, string(types.ErrRateLimitExceeded),
					fmt.Sprintf("Rate limit exceeded. Try again in %d seconds. Limit: %s", result.RetryAfter, result.Limit))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// IPStrategy identifies clients by IP address
func IPStrategy(r *http.Request) string {
	return getClientIP(r)
}

// UserIDStrategy identifies authenticated clients by user ID
func UserIDStrategy(r *http.Request) string {
	ctx := r.Context()
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		// Fall back to IP if not authenticated
		return "ip:" + getClientIP(r)
	}
	return "user:" + userID
}

// CompositeStrategy combines IP and user ID for authenticated users
func CompositeStrategy(r *http.Request) string {
	ctx := r.Context()
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		return "ip:" + getClientIP(r)
	}
	return "user:" + userID + ":" + getClientIP(r)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP (leftmost is the original client)
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}

// StrategyFromNames creates a composite strategy from strategy names
func StrategyFromNames(names []string) IdentifierStrategy {
	if len(names) == 0 {
		return IPStrategy
	}

	return func(r *http.Request) string {
		var parts []string
		for _, name := range names {
			switch name {
			case "ip":
				parts = append(parts, "ip:"+getClientIP(r))
			case "user_id":
				ctx := r.Context()
				if userID, ok := ctx.Value(types.UserIDKey).(string); ok && userID != "" {
					parts = append(parts, "user:"+userID)
				}
			}
		}
		if len(parts) == 0 {
			return "ip:" + getClientIP(r)
		}
		return strings.Join(parts, ":")
	}
}
