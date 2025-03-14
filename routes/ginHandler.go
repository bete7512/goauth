// auth/routes/gin_routes.go
package routes

import (
	"net/http"

	"github.com/bete7512/goauth/routes/handlers"
	oauthhandlers "github.com/bete7512/goauth/routes/handlers/oauth"
	"github.com/bete7512/goauth/types"
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
func (h *GinHandler) GinMiddleWare(r *gin.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: add middleware here
		r.Use(gin.Recovery())
		c.Next()
	}
}

// func (h *GinHandler) GinAdminMiddleWare() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// TODO: add middleware here
// 		c.Next()
// 	}
// }

func (h *GinHandler) SetupRoutes(r *gin.Engine) {
	auth := r.Group(h.Handler.Auth.Config.BasePath)
	{
		// @Summary Register a new user
		// @Description Register a new user
		// @Tags Auth
		// @Accept json
		// @Produce json
		// @Param registerUser body RegisterUser true "Register User"
		// @Success 200 {object} RegisterUserResponse
		// @Router /register [post]
		auth.POST("/register", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteRegister, h.Handler.HandleRegister)))
		auth.POST("/login", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteLogin, h.Handler.HandleLogin)))
		auth.POST("/logout", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteLogout, h.Handler.HandleLogout)))
		auth.POST("/refresh-token", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteRefreshToken, h.Handler.HandleRefreshToken)))
		auth.POST("/forgot-password", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteForgotPassword, h.Handler.HandleForgotPassword)))
		auth.POST("/reset-password", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteResetPassword, h.Handler.HandleResetPassword)))
		auth.POST("/update-profile", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteUpdateProfile, h.Handler.HandleUpdateProfile)))
		auth.POST("/deactivate-user", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteDeactivateUser, h.Handler.HandleDeactivateUser)))
		auth.GET("/me", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteGetMe, h.Handler.HandleGetUser)))
		auth.POST("/enable-two-factor", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteEnableTwoFactor, h.Handler.HandleEnableTwoFactor)))
		auth.POST("/verify-two-factor", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteVerifyTwoFactor, h.Handler.HandleVerifyTwoFactor)))
		auth.POST("/disable-two-factor", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteDisableTwoFactor, h.Handler.HandleDisableTwoFactor)))
		auth.POST("/verify-email", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteVerifyEmail, h.Handler.HandleVerifyEmail)))
		auth.POST("/resend-verification-email", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteResendVerificationEmail, h.Handler.HandleResendVerificationEmail)))
		// auth.GET("/get-all-users", h.GinAdminMiddleWare(), func(ctx *gin.Context) {
		// 	ctx.JSON(http.StatusOK, gin.H{"users": []string{"user1", "user2", "user3"}})
		// })
		for _, oauth := range h.Handler.Auth.Config.Providers.Enabled {
			switch oauth {
			case "google":
				google := oauthhandlers.NewGoogleOauth(h.Handler.Auth)
				auth.POST("/oauth/google", ginHandlerWrapper(google.SignIn))
				auth.POST("/oauth/google/callback", ginHandlerWrapper(google.Callback))
			case "github":
				// TODO: continue working for other providers
			}
		}
	}
}
