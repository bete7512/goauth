// auth/routes/http_routes.go
package routes

import (
	"log"
	"net/http"

	"github.com/bete7512/goauth/routes/handlers"
	oauthhandlers "github.com/bete7512/goauth/routes/handlers/oauth"
	"github.com/bete7512/goauth/types"
)

type HttpHandler struct {
	Handler handlers.AuthHandler
}

func NewHttpHandler(handler handlers.AuthHandler) *HttpHandler {
	return &HttpHandler{Handler: handler}
}

func (h *HttpHandler) SetupRoutes(s *http.ServeMux) {
	// Register routes with hook middleware
	s.HandleFunc("/auth/register", h.Handler.WithHooks(types.RouteRegister, h.Handler.HandleRegister))
	s.HandleFunc("/auth/login", h.Handler.WithHooks(types.RouteLogin, h.Handler.HandleLogin))
	s.HandleFunc("/auth/logout", h.Handler.WithHooks(types.RouteLogout, h.Handler.HandleLogout))
	s.HandleFunc("/auth/refresh-token", h.Handler.WithHooks(types.RouteRefreshToken, h.Handler.HandleRefreshToken))
	s.HandleFunc("/auth/forgot-password", h.Handler.WithHooks(types.RouteForgotPassword, h.Handler.HandleForgotPassword))
	s.HandleFunc("/auth/reset-password", h.Handler.WithHooks(types.RouteResetPassword, h.Handler.HandleResetPassword))
	s.HandleFunc("/auth/update-profile", h.Handler.WithHooks(types.RouteUpdateProfile, h.Handler.HandleUpdateProfile))
	s.HandleFunc("/auth/deactivate-user", h.Handler.WithHooks(types.RouteDeactivateUser, h.Handler.HandleDeactivateUser))
	s.HandleFunc("/auth/me", h.Handler.WithHooks(types.RouteGetMe, h.Handler.HandleGetUser))
	s.HandleFunc("/auth/enable-two-factor", h.Handler.WithHooks(types.RouteEnableTwoFactor, h.Handler.HandleEnableTwoFactor))
	s.HandleFunc("/auth/verify-two-factor", h.Handler.WithHooks(types.RouteVerifyTwoFactor, h.Handler.HandleVerifyTwoFactor))
	s.HandleFunc("/auth/disable-two-factor", h.Handler.WithHooks(types.RouteDisableTwoFactor, h.Handler.HandleDisableTwoFactor))
	s.HandleFunc("/auth/verify-email", h.Handler.WithHooks(types.RouteVerifyEmail, h.Handler.HandleVerifyEmail))
	s.HandleFunc("/auth/resend-verification-email", h.Handler.WithHooks(types.RouteResendVerificationEmail, h.Handler.HandleResendVerificationEmail))
	// OAuth routes
	for _, oauth := range h.Handler.Auth.Config.Providers.Enabled {
		switch oauth {
		case "google":
			google := oauthhandlers.NewGoogleOauth(h.Handler.Auth)
			s.HandleFunc("/auth/oauth/google", google.SignIn)
			s.HandleFunc("/auth/oauth/google/callback", google.Callback)
		case "github":
			// TODO: continue working for other providers
		}
	}
}

// HttpMiddleWare
func (h *HttpHandler) HttpMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Http Middleware added")
		next.ServeHTTP(w, r)
	})
}

// every gin route should be added here
// TODO: think about middleware here
