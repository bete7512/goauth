package routes

import (
	"net/http"

	"github.com/bete7512/goauth/docs"
	"github.com/bete7512/goauth/routes/handlers"
	oauthhandlers "github.com/bete7512/goauth/routes/handlers/oauth"
	middleware "github.com/bete7512/goauth/routes/middlewares"
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

func (h *GinHandler) SetupRoutes(r *gin.Engine) {
	auth := r.Group(h.Handler.Auth.Config.BasePath)
	{
		if h.Handler.Auth.Config.Swagger.Enable {
			docs.RegisterGinRoutes(r, docs.SwaggerInfo{
				Version:     h.Handler.Auth.Config.Swagger.Version,
				Host:        h.Handler.Auth.Config.Swagger.Host,
				BasePath:    h.Handler.Auth.Config.BasePath,
				Title:       h.Handler.Auth.Config.Swagger.Title,
				DocPath:     h.Handler.Auth.Config.Swagger.DocPath,
				Description: h.Handler.Auth.Config.Swagger.Description,
				Schemes:     []string{"http", "https"},
			})
		}
		auth.POST("/register", ginHandlerWrapper(h.Handler.WithHooks(
			types.RouteRegister, h.Handler.HandleRegister)))

		if h.Handler.Auth.Config.AuthConfig.EnableRateLimiter {
			if _, exists := h.Handler.Auth.Config.RateLimiter.Routes[types.RouteLogin]; exists {
				auth.POST("/login", ginHandlerWrapper(h.Handler.WithHooks(
					types.RouteLogin, middleware.RateLimiterMiddleware(*h.Handler.Auth.RateLimiter, h.Handler.Auth.Config.RateLimiter, types.RouteLogin, h.Handler.HandleLogin))))
			}
		} else {
			auth.POST("/login", ginHandlerWrapper(h.Handler.WithHooks(
				types.RouteLogin, h.Handler.HandleLogin)))
		}
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
		for _, oauth := range h.Handler.Auth.Config.Providers.Enabled {
			switch oauth {
			case "google":
				google := oauthhandlers.NewGoogleOauth(h.Handler.Auth)
				auth.GET("/oauth/google", ginHandlerWrapper(google.SignIn))
				auth.GET("/oauth/google/callback", ginHandlerWrapper(google.Callback))
			case "github":
				github := oauthhandlers.NewGitHubOauth(h.Handler.Auth)
				auth.GET("/oauth/github", ginHandlerWrapper(github.SignIn))
				auth.GET("/oauth/github/callback", ginHandlerWrapper(github.Callback))
			case "facebook":
				facebook := oauthhandlers.NewFacebookOauth(h.Handler.Auth)
				auth.GET("/oauth/facebook", ginHandlerWrapper(facebook.SignIn))
				auth.GET("/oauth/facebook/callback", ginHandlerWrapper(facebook.Callback))
			case "microsoft":
				microsoft := oauthhandlers.NewMicrosoftOauth(h.Handler.Auth)
				auth.GET("/oauth/microsoft", ginHandlerWrapper(microsoft.SignIn))
				auth.GET("/oauth/microsoft/callback", ginHandlerWrapper(microsoft.Callback))
			case "apple":
				apple := oauthhandlers.NewAppleOauth(h.Handler.Auth)
				auth.GET("/oauth/apple", ginHandlerWrapper(apple.SignIn))
				auth.GET("/oauth/apple/callback", ginHandlerWrapper(apple.Callback))
			case "discord":
				discord := oauthhandlers.NewDiscordOauth(h.Handler.Auth)
				auth.GET("/oauth/discord", ginHandlerWrapper(discord.SignIn))
				auth.GET("/oauth/discord/callback", ginHandlerWrapper(discord.Callback))
			case "twitter":
				twitter := oauthhandlers.NewTwitterOauth(h.Handler.Auth)
				auth.GET("/oauth/twitter", ginHandlerWrapper(twitter.SignIn))
				auth.GET("/oauth/twitter/callback", ginHandlerWrapper(twitter.Callback))
			case "linkedin":
				linkedin := oauthhandlers.NewLinkedInOauth(h.Handler.Auth)
				auth.GET("/oauth/linkedin", ginHandlerWrapper(linkedin.SignIn))
				auth.GET("/oauth/linkedin/callback", ginHandlerWrapper(linkedin.Callback))
				
			default:
				// h.Handler.Auth.Logger.Warnf("OAuth provider %s is not supported", oauth)

			}
		}
	}
}
