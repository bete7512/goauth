package middlewares

import (
	"net"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/captcha/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

const (
	defaultHeaderName    = "X-Captcha-Token"
	defaultFormFieldName = "captcha_token"
)

// NewCaptchaMiddleware creates a middleware that verifies captcha tokens
// using the configured provider before allowing the request through.
// trusted lists reverse proxies whose forwarded headers identify the client.
func NewCaptchaMiddleware(service *services.CaptchaService, cfg *config.CaptchaModuleConfig, trusted []net.IPNet) func(http.Handler) http.Handler {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = defaultHeaderName
	}
	formFieldName := cfg.FormFieldName
	if formFieldName == "" {
		formFieldName = defaultFormFieldName
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no provider is configured, skip verification
			if service.Provider() == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Extract captcha token from header, then form fields
			token := r.Header.Get(headerName)
			if token == "" {
				token = r.FormValue(formFieldName)
			}
			if token == "" {
				token = r.FormValue("cf-turnstile-response")
			}
			if token == "" {
				token = r.FormValue("g-recaptcha-response")
			}

			if token == "" {
				http_utils.RespondError(w, http.StatusForbidden, string(types.ErrCaptchaRequired), "Captcha token required")
				return
			}

			clientIP := http_utils.ClientIP(r, trusted)
			valid, err := service.Verify(r.Context(), token, clientIP)
			if err != nil || !valid {
				http_utils.RespondError(w, http.StatusForbidden, string(types.ErrCaptchaFailed), "Captcha verification failed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
