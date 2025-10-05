package middlewares

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/captcha/services"
)

// NewCaptchaMiddleware creates a captcha verification middleware
func NewCaptchaMiddleware(service *services.CaptchaService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provider := service.GetProvider()
			if provider == nil {
				// No captcha provider configured, skip verification
				next.ServeHTTP(w, r)
				return
			}

			// Get captcha token from header or form
			token := r.Header.Get("X-Captcha-Token")
			if token == "" {
				token = r.FormValue("captcha_token")
			}
			if token == "" {
				token = r.FormValue("cf-turnstile-response") // Cloudflare's default field
			}
			if token == "" {
				token = r.FormValue("g-recaptcha-response") // Google's default field
			}

			if token == "" {
				http.Error(w, "Captcha token required", http.StatusBadRequest)
				return
			}

			// Verify captcha
			clientIP := getClientIP(r)
			valid, err := service.Verify(r.Context(), token, clientIP)
			if err != nil || !valid {
				http.Error(w, "Captcha verification failed", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP
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
