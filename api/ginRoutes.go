package api

import (
	"net/http"

	middleware "github.com/bete7512/goauth/api/middlewares"
	"github.com/bete7512/goauth/api/routes"
	oauthRoutes "github.com/bete7512/goauth/api/routes/oauth"
	"github.com/bete7512/goauth/docs"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
)

type GinHandler struct {
	Handler routes.AuthHandler
}

func NewGinHandler(handler routes.AuthHandler) *GinHandler {
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
		auth.POST("/register", h.routeWithOptionalMiddlwares(types.RouteRegister, h.Handler.HandleRegister))
		auth.POST("/login", h.routeWithOptionalMiddlwares(types.RouteLogin, h.Handler.HandleLogin))
		auth.POST("/logout", h.routeWithOptionalMiddlwares(types.RouteLogout, h.Handler.HandleLogout))
		auth.POST("/refresh-token", h.routeWithOptionalMiddlwares(types.RouteRefreshToken, h.Handler.HandleRefreshToken))
		auth.POST("/forgot-password", h.routeWithOptionalMiddlwares(types.RouteForgotPassword, h.Handler.HandleForgotPassword))
		auth.POST("/reset-password", h.routeWithOptionalMiddlwares(types.RouteResetPassword, h.Handler.HandleResetPassword))
		auth.POST("/update-profile", h.routeWithOptionalMiddlwares(types.RouteUpdateProfile, h.Handler.HandleUpdateProfile))
		auth.POST("/deactivate-user", h.routeWithOptionalMiddlwares(types.RouteDeactivateUser, h.Handler.HandleDeactivateUser))
		auth.GET("/me", h.routeWithOptionalMiddlwares(types.RouteGetMe, h.Handler.HandleGetUser))
		auth.POST("/enable-two-factor", h.routeWithOptionalMiddlwares(types.RouteEnableTwoFactor, h.Handler.HandleEnableTwoFactor))
		auth.POST("/verify-two-factor", h.routeWithOptionalMiddlwares(types.RouteVerifyTwoFactor, h.Handler.HandleVerifyTwoFactor))
		auth.POST("/disable-two-factor", h.routeWithOptionalMiddlwares(types.RouteDisableTwoFactor, h.Handler.HandleDisableTwoFactor))
		auth.POST("/verify-email", h.routeWithOptionalMiddlwares(types.RouteVerifyEmail, h.Handler.HandleVerifyEmail))
		auth.POST("/resend-verification-email", h.routeWithOptionalMiddlwares(types.RouteResendVerificationEmail, h.Handler.HandleResendVerificationEmail))
		for _, oauth := range h.Handler.Auth.Config.Providers.Enabled {
			switch oauth {
			case "google":
				google := oauthRoutes.NewGoogleOauth(h.Handler.Auth)
				auth.GET("/oauth/google", ginHandlerWrapper(google.SignIn))
				auth.GET("/oauth/google/callback", ginHandlerWrapper(google.Callback))
			case "github":
				github := oauthRoutes.NewGitHubOauth(h.Handler.Auth)
				auth.GET("/oauth/github", ginHandlerWrapper(github.SignIn))
				auth.GET("/oauth/github/callback", ginHandlerWrapper(github.Callback))
			case "facebook":
				facebook := oauthRoutes.NewFacebookOauth(h.Handler.Auth)
				auth.GET("/oauth/facebook", ginHandlerWrapper(facebook.SignIn))
				auth.GET("/oauth/facebook/callback", ginHandlerWrapper(facebook.Callback))
			case "microsoft":
				microsoft := oauthRoutes.NewMicrosoftOauth(h.Handler.Auth)
				auth.GET("/oauth/microsoft", ginHandlerWrapper(microsoft.SignIn))
				auth.GET("/oauth/microsoft/callback", ginHandlerWrapper(microsoft.Callback))
			case "apple":
				apple := oauthRoutes.NewAppleOauth(h.Handler.Auth)
				auth.GET("/oauth/apple", ginHandlerWrapper(apple.SignIn))
				auth.GET("/oauth/apple/callback", ginHandlerWrapper(apple.Callback))
			case "discord":
				discord := oauthRoutes.NewDiscordOauth(h.Handler.Auth)
				auth.GET("/oauth/discord", ginHandlerWrapper(discord.SignIn))
				auth.GET("/oauth/discord/callback", ginHandlerWrapper(discord.Callback))
			case "twitter":
				twitter := oauthRoutes.NewTwitterOauth(h.Handler.Auth)
				auth.GET("/oauth/twitter", ginHandlerWrapper(twitter.SignIn))
				auth.GET("/oauth/twitter/callback", ginHandlerWrapper(twitter.Callback))
			case "linkedin":
				linkedin := oauthRoutes.NewLinkedInOauth(h.Handler.Auth)
				auth.GET("/oauth/linkedin", ginHandlerWrapper(linkedin.SignIn))
				auth.GET("/oauth/linkedin/callback", ginHandlerWrapper(linkedin.Callback))
			default:
				// h.Handler.Auth.Logger.Warnf("OAuth provider %s is not supported", oauth)
			}
		}
	}
}

func (h *GinHandler) routeWithOptionalMiddlwares(route string, handler http.HandlerFunc) gin.HandlerFunc {
	// Add hooks
	baseHandler := h.Handler.WithHooks(route, handler)
	// TODO: check for  rate limiter
	// TODO: check for recaptcha
	// Check if rate limiter is enabled and configured for the route
	if h.Handler.Auth.Config.EnableRateLimiter {
		if _, exists := h.Handler.Auth.Config.RateLimiter.Routes[route]; exists {
			return ginHandlerWrapper(middleware.RateLimiterMiddleware(
				*h.Handler.Auth.RateLimiter,
				h.Handler.Auth.Config.RateLimiter,
				route,
				baseHandler,
			))
		}
	}
	

	// Fallback without rate limiting
	return ginHandlerWrapper(baseHandler)
}
