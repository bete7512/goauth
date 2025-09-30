package middlewares

import (
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/types"
)

func (m *Middleware) RecaptchaMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recaptchaToken := r.Header.Get("X-Recaptcha-Token")
		if recaptchaToken == "" {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "recaptcha token is required")
			return
		}
		ip := utils.GetIpFromRequest(r)

		ok, err := m.Auth.RecaptchaManager.Verify(r.Context(), recaptchaToken, ip)
		if err != nil {
			utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "recaptcha verification failed: "+err.Error())
			return
		}
		if !ok {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "recaptcha verification failed")
			return
		}
		next.ServeHTTP(w, r)
	}
}
