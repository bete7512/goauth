package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/api/docs"
	"github.com/bete7512/goauth/internal/api/handlers"
	oauthRoutes "github.com/bete7512/goauth/internal/api/handlers/oauth"
	"github.com/bete7512/goauth/internal/api/middlewares"
	"github.com/bete7512/goauth/pkg/config"
)

// AuthHandler is the main authentication service
type AuthHandler struct {
	Auth       *config.Auth
	handlers   *handlers.AuthHandler
	middleware *middlewares.Middleware
}

// NewAuthHandler creates a new authentication service
func NewAuthHandler(auth *config.Auth) *AuthHandler {
	routes := handlers.NewAuthHandler(auth)
	middleware := middlewares.NewMiddleware(auth)
	service := &AuthHandler{
		Auth:       auth,
		handlers:   routes,
		middleware: middleware,
	}
	return service
}

// GetAuthMiddleware returns standard HTTP middleware for protecting routes
func (a *AuthHandler) GetAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedHandler := a.middleware.AuthMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetAdminMiddleware returns admin-only HTTP middleware
func (a *AuthHandler) GetAdminMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedHandler := a.middleware.AdminMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetRecaptchaMiddleware returns recaptcha middleware
func (a *AuthHandler) GetRecaptchaMiddleware(routeName string) func(http.Handler) http.Handler {
	if !a.Auth.Config.Security.Recaptcha.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	if _, needsRecaptcha := a.Auth.Config.Security.Recaptcha.Routes[routeName]; !needsRecaptcha {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedHandler := a.middleware.RecaptchaMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetCSRFMiddleware returns CSRF middleware
func (a *AuthHandler) GetCSRFMiddleware(routeName string) func(http.Handler) http.Handler {
	if !a.Auth.Config.Features.EnableCSRF || a.Auth.Config.AuthConfig.Methods.Type != config.AuthenticationTypeCookie {
		return func(next http.Handler) http.Handler { return next }
	}
	if _, needsCSRF := a.Auth.Config.Security.CSRF.Routes[routeName]; !needsCSRF {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedHandler := a.middleware.CSRFMiddleware(next.ServeHTTP)
			wrappedHandler(w, r)
		})
	}
}

// GetRateLimitMiddleware returns rate limiting middleware
func (a *AuthHandler) GetRateLimitMiddleware(routeName string) func(http.Handler) http.Handler {
	if !a.Auth.Config.Features.EnableRateLimiter {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this route needs rate limiting
			if _, needsRateLimit := a.Auth.Config.Security.RateLimiter.Routes[routeName]; needsRateLimit {
				wrappedHandler := a.middleware.RateLimiterMiddleware(a.Auth.RateLimiter, &a.Auth.Config.Security.RateLimiter, routeName, next.ServeHTTP)
				wrappedHandler(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// responseCaptureWriter captures the response data for after hooks
type responseCaptureWriter struct {
	http.ResponseWriter
	statusCode int
	body       []byte
	captured   bool
}

func (w *responseCaptureWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseCaptureWriter) Write(data []byte) (int, error) {
	if !w.captured {
		w.body = make([]byte, len(data))
		copy(w.body, data)
		w.captured = true
	}
	return w.ResponseWriter.Write(data)
}

func (a *AuthHandler) GetHookMiddleware(routeName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hasBeforeHook := a.Auth.HookManager.GetBeforeHook(routeName) != nil
			hasAfterHook := a.Auth.HookManager.GetAfterHook(routeName) != nil

			// If no hooks, execute normally
			if !hasBeforeHook && !hasAfterHook {
				next.ServeHTTP(w, r)
				return
			}

			// Always preserve request body if we have any hooks
			var requestBody []byte
			if r.Body != nil {
				requestBody, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewBuffer(requestBody))
			}

			// Add request data to context
			ctx := r.Context()
			if len(requestBody) > 0 {
				ctx = context.WithValue(ctx, config.RequestDataKey, requestBody)
				r = r.WithContext(ctx)
			}

			// Execute before hooks
			if hasBeforeHook {
				proceed := a.Auth.HookManager.ExecuteBeforeHooks(routeName, w, r)
				if !proceed {
					return
				}
			}

			// Handle after hooks
			if hasAfterHook {
				captureWriter := &responseCaptureWriter{ResponseWriter: w}
				next.ServeHTTP(captureWriter, r)

				// Update context with response data
				if captureWriter.captured {
					ctx = context.WithValue(ctx, config.ResponseDataKey, captureWriter.body)
					ctx = context.WithValue(ctx, config.ResponseStatusCodeKey, captureWriter.statusCode)
					r = r.WithContext(ctx)
				}

				// Execute after hooks - they should only read from context, not write to response
				a.Auth.HookManager.ExecuteAfterHooks(routeName, captureWriter, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// buildMiddlewareChain builds the middleware chain for a route
func (a *AuthHandler) buildMiddlewareChain(routeName string, handler http.HandlerFunc) http.HandlerFunc {
	// Start with the base handler
	var finalHandler http.Handler = http.HandlerFunc(handler)

	// TODO check whether handling middleware with if clause or like this
	// Add hook middleware
	finalHandler = a.GetHookMiddleware(routeName)(finalHandler)

	// Add recaptcha middleware
	finalHandler = a.GetRecaptchaMiddleware(routeName)(finalHandler)

	// Add CSRF middleware
	finalHandler = a.GetCSRFMiddleware(routeName)(finalHandler)

	// Add rate limiting middleware
	finalHandler = a.GetRateLimitMiddleware(routeName)(finalHandler)

	return finalHandler.ServeHTTP
}

// Hook management methods
func (a *AuthHandler) RegisterBeforeHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.Auth.HookManager.RegisterBeforeHook(route, hook)
}

func (a *AuthHandler) RegisterAfterHook(route string, hook func(http.ResponseWriter, *http.Request) (bool, error)) error {
	return a.Auth.HookManager.RegisterAfterHook(route, hook)
}

// GetRoutes returns all routes for manual registration
func (a *AuthHandler) GetRoutes() []config.RouteInfo {
	basePath := a.Auth.Config.App.BasePath
	if basePath == "" {
		basePath = ""
	}

	routes := []config.RouteInfo{
		// Public routes
		{Method: "POST", Path: basePath + "/register", Name: config.RouteRegister, Handler: a.handlers.HandleRegister},
		{Method: "POST", Path: basePath + "/login", Name: config.RouteLogin, Handler: a.handlers.HandleLogin},
		{Method: "POST", Path: basePath + "/refresh-token", Name: config.RouteRefreshToken, Handler: a.handlers.HandleRefreshToken},
		{Method: "POST", Path: basePath + "/forgot-password", Name: config.RouteForgotPassword, Handler: a.handlers.HandleForgotPassword},
		{Method: "POST", Path: basePath + "/reset-password", Name: config.RouteResetPassword, Handler: a.handlers.HandleResetPassword},
		{Method: "POST", Path: basePath + "/send-magic-link", Name: config.RouteSendMagicLink, Handler: a.handlers.SendMagicLink},
		{Method: "POST", Path: basePath + "/verify-magic-link", Name: config.RouteVerifyMagicLink, Handler: a.handlers.VerifyMagicLink},
		{Method: "GET", Path: basePath + "/verify-magic-link", Name: config.RouteVerifyMagicLink, Handler: a.handlers.VerifyMagicLink},
		{Method: "POST", Path: basePath + "/verification/email/send", Name: config.RouteSendEmailVerification, Handler: a.handlers.HandleSendEmailVerification},
		{Method: "GET", Path: basePath + "/verification/email/verify", Name: config.RouteVerifyEmail, Handler: a.handlers.HandleVerifyEmail},
		{Method: "POST", Path: basePath + "/verification/email/verify", Name: config.RouteVerifyEmail, Handler: a.handlers.HandleVerifyEmail},
		{Method: "POST", Path: basePath + "/verification/phone/send", Name: config.RouteSendPhoneVerification, Handler: a.handlers.HandleSendPhoneVerification},
		{Method: "POST", Path: basePath + "/verification/phone/verify", Name: config.RouteVerifyPhone, Handler: a.handlers.HandleVerifyPhone},
		{Method: "GET", Path: basePath + "/verification/phone/verify", Name: config.RouteVerifyPhone, Handler: a.handlers.HandleVerifyPhone},
		{Method: "POST", Path: basePath + "/register/invitation", Name: "register.invitation", Handler: a.handlers.HandleRegisterWithInvitation},

		// Protected routes
		{Method: "POST", Path: basePath + "/action/confirm", Name: "action.confirm", Handler: a.middleware.AuthMiddleware(a.handlers.HandleSendActionConfirmation)},
		{Method: "POST", Path: basePath + "/action/verify", Name: "action.verify", Handler: a.middleware.AuthMiddleware(a.handlers.HandleVerifyActionConfirmation)},
		{Method: "GET", Path: basePath + "/me", Name: config.RouteGetMe, Handler: a.middleware.AuthMiddleware(a.handlers.HandleGetUser)},
		{Method: "POST", Path: basePath + "/update-profile", Name: config.RouteUpdateProfile, Handler: a.middleware.AuthMiddleware(a.handlers.HandleUpdateProfile)},
		{Method: "POST", Path: basePath + "/logout", Name: config.RouteLogout, Handler: a.middleware.AuthMiddleware(a.handlers.HandleLogout)},
		{Method: "POST", Path: basePath + "/deactivate-user", Name: config.RouteDeactivateUser, Handler: a.middleware.AuthMiddleware(a.handlers.HandleDeactivateUser)},
		{Method: "POST", Path: basePath + "/enable-two-factor", Name: config.RouteEnableTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleEnableTwoFactor)},
		{Method: "POST", Path: basePath + "/verify-two-factor", Name: config.RouteVerifyTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleVerifyTwoFactor)},
		{Method: "POST", Path: basePath + "/disable-two-factor", Name: config.RouteDisableTwoFactor, Handler: a.middleware.AuthMiddleware(a.handlers.HandleDisableTwoFactor)},
		{Method: "GET", Path: basePath + "/csrf/token", Name: "csrf.token", Handler: a.middleware.AuthMiddleware(a.handlers.HandleGetCSRFToken)},

		// Admin routes
		{Method: "GET", Path: basePath + "/admin/users", Name: "admin.users.list", Handler: a.middleware.AdminMiddleware(a.handlers.HandleListUsers)},
		{Method: "GET", Path: basePath + "/admin/users/{id}", Name: "admin.users.get", Handler: a.middleware.AdminMiddleware(a.handlers.HandleGetUser)},
		{Method: "PUT", Path: basePath + "/admin/users/{id}", Name: "admin.users.update", Handler: a.middleware.AdminMiddleware(a.handlers.HandleUpdateUser)},
		{Method: "PATCH", Path: basePath + "/admin/users/{id}", Name: "admin.users.patch", Handler: a.middleware.AdminMiddleware(a.handlers.HandleUpdateUser)},
		{Method: "DELETE", Path: basePath + "/admin/users/{id}", Name: "admin.users.delete", Handler: a.middleware.AdminMiddleware(a.handlers.HandleDeleteUser)},
		{Method: "POST", Path: basePath + "/admin/users/{id}/activate", Name: "admin.users.activate", Handler: a.middleware.AdminMiddleware(a.handlers.HandleActivateUser)},
		{Method: "POST", Path: basePath + "/admin/users/bulk", Name: "admin.users.bulk", Handler: a.middleware.AdminMiddleware(a.handlers.HandleBulkAction)},
		// {Method: "GET", Path: basePath + "/admin/stats", Name: "admin.stats", Handler: a.middleware.AdminMiddleware(a.handlers.HandleSystemStats)},
		{Method: "GET", Path: basePath + "/admin/audit-logs", Name: "admin.audit-logs", Handler: a.middleware.AdminMiddleware(a.handlers.HandleGetAuditLogs)},
		// {Method: "GET", Path: basePath + "/admin/health", Name: "admin.health", Handler: a.middleware.AdminMiddleware(a.handlers.HandleSystemHealth)},
		{Method: "GET", Path: basePath + "/admin/users/export", Name: "admin.users.export", Handler: a.middleware.AdminMiddleware(a.handlers.HandleExportUsers)},
		{Method: "POST", Path: basePath + "/admin/invitations", Name: "admin.invitations.create", Handler: a.middleware.AdminMiddleware(a.handlers.HandleInviteUser)},
		{Method: "GET", Path: basePath + "/admin/invitations", Name: "admin.invitations.list", Handler: a.middleware.AdminMiddleware(a.handlers.HandleListInvitations)},
		{Method: "DELETE", Path: basePath + "/admin/invitations/{id}", Name: "admin.invitations.cancel", Handler: a.middleware.AdminMiddleware(a.handlers.HandleCancelInvitation)},
	}

	// Add OAuth routes
	for _, providerName := range a.Auth.Config.Providers.Enabled {
		providerPath := basePath + "/oauth/" + string(providerName)

		var provider interface {
			SignIn(w http.ResponseWriter, r *http.Request)
			Callback(w http.ResponseWriter, r *http.Request)
		}

		switch providerName {
		case config.Google:
			provider = oauthRoutes.NewGoogleOauth(a.Auth)
		case config.GitHub:
			provider = oauthRoutes.NewGitHubOauth(a.Auth)
		default:
			continue
		}

		routes = append(routes,
			config.RouteInfo{Method: "GET", Path: providerPath, Name: "oauth." + string(providerName) + ".signin", Handler: provider.SignIn},
			config.RouteInfo{Method: "GET", Path: providerPath + "/callback", Name: "oauth." + string(providerName) + ".callback", Handler: provider.Callback},
		)
	}

	// Add Swagger routes if enabled
	if a.Auth.Config.App.Swagger.Enable {
		swaggerRoutes := a.getSwaggerRoutes(basePath)
		routes = append(routes, swaggerRoutes...)
	}

	return routes
}

// getSwaggerRoutes returns swagger-related routes
func (a *AuthHandler) getSwaggerRoutes(basePath string) []config.RouteInfo {
	swaggerInfo := docs.SwaggerInfo{
		Title:       a.Auth.Config.App.Swagger.Title,
		Description: a.Auth.Config.App.Swagger.Description,
		Version:     a.Auth.Config.App.Swagger.Version,
		Host:        a.Auth.Config.App.Swagger.Host,
		BasePath:    basePath,
		DocPath:     a.Auth.Config.App.Swagger.DocPath,
		Schemes:     []string{"http", "https"},
	}

	// Create the swagger handler
	swaggerHandler := docs.NewSwaggerHandler(swaggerInfo)

	// Create handler functions that delegate to the swagger handler
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		swaggerHandler.ServeHTTP(w, r)
	}

	jsonHandler := func(w http.ResponseWriter, r *http.Request) {
		swaggerHandler.ServeHTTP(w, r)
	}

	docPath := strings.TrimPrefix(a.Auth.Config.App.Swagger.DocPath, "/")

	return []config.RouteInfo{
		// Main swagger UI route - this serves the HTML interface
		{Method: "GET", Path: basePath + "/" + docPath + "/", Name: "swagger.ui", Handler: mainHandler},
		{Method: "GET", Path: basePath + "/" + docPath, Name: "swagger.ui.redirect", Handler: mainHandler},

		// JSON spec route - this serves the OpenAPI JSON specification
		{Method: "GET", Path: basePath + "/" + docPath + "/swagger.json", Name: "swagger.json", Handler: jsonHandler},
		{Method: "GET", Path: basePath + "/swagger.json", Name: "swagger.json.alt", Handler: jsonHandler},
	}
}

// GetWrappedHandler returns a handler with all middleware applied
func (a *AuthHandler) GetWrappedHandler(routeInfo config.RouteInfo) http.HandlerFunc {
	handler := routeInfo.Handler
	// Build middleware chain
	return a.buildMiddlewareChain(routeInfo.Name, handler)
}
