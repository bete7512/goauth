package handlers

import (
	"net/http"

	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// GetToken generates a CSRF token, sets it as a cookie, and returns it in the response.
// The cookie is NOT HttpOnly so that client-side JavaScript can read it
// and include it in the X-CSRF-Token header on subsequent requests.
func (h *CSRFHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	token, err := h.service.GenerateToken()
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate CSRF token")
		return
	}

	secure := h.config.Secure
	sameSite := h.config.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.service.CookieName(),
		Value:    token,
		Path:     h.service.CookiePath(),
		Domain:   h.service.CookieDomain(),
		MaxAge:   int(h.service.TokenExpiry().Seconds()),
		Secure:   secure,
		HttpOnly: false, // Client JS must read this cookie for double-submit
		SameSite: sameSite,
	})

	http_utils.RespondSuccess(w, map[string]string{"csrf_token": token}, nil)
}
