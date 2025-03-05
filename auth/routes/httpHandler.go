// auth/routes/http_routes.go
package routes

import (
	"log"
	"net/http"

	"github.com/bete7512/go-auth/auth/routes/handlers"
	"github.com/bete7512/go-auth/auth/types"
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
	// s.HandleFunc("/auth/logout", h.Handler.WithHooks(types.RouteLogout, h.Handler.HandleLogout))
	// s.HandleFunc("/auth/refresh-token", h.Handler.WithHooks(types.RouteRefreshToken, h.Handler.HandleRefreshToken))
	
	// Additional routes would be added here as implemented
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
