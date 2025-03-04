// auth/routes/gin_routes.go
package routes

import (
	"net/http"

	"github.com/bete7512/go-auth/auth/routes/handlers"
	"github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

type GinHandler struct {
	Handler handlers.AuthHandler
}

func NewGinHandler(handler handlers.AuthHandler) *GinHandler {
	return &GinHandler{Handler: handler}
}

// ginHandlerWrapper adapts a standard http.HandlerFunc to gin.HandlerFunc
func ginHandlerWrapper(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

func (h *GinHandler) SetupRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		// Use the WithHooks wrapper for each route
		auth.POST("/register", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteRegister, h.Handler.HandleRegister)))

		auth.POST("/login", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteLogin, h.Handler.HandleLogin)))
		// auth.POST("/logout", ginHandlerWrapper(h.Handler.WithHooks(
		// 	types.RouteLogout, h.Handler.HandleLogout)))

		// auth.POST("/refresh-token", ginHandlerWrapper(h.Handler.WithHooks(
		// 	types.RouteRefreshToken, h.Handler.HandleRefreshToken)))

		// Additional routes would be added here as implemented
	}
}

// every gin route should be added here
// TODO: think about middleware here
