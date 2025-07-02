package middlewares

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
)

func (m *Middleware) RecaptchaMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recaptchaToken := r.Header.Get("X-Recaptcha-Token")
		if recaptchaToken == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "recaptcha token is required", nil)
			return
		}
		ip := utils.GetIpFromRequest(r)

		ok, err := m.Auth.RecaptchaManager.Verify(r.Context(), recaptchaToken, ip)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "recaptcha verification failed: "+err.Error(), nil)
			return
		}
		if !ok {
			utils.RespondWithError(w, http.StatusBadRequest, "recaptcha verification failed", nil)
			return
		}
		next.ServeHTTP(w, r)
	}
}
