package frameworks

import (
	"net/http"

	"github.com/bete7512/goauth/api/core"
	"github.com/labstack/echo/v4"
)

// EchoAdapter adapts the core authentication routes to the Echo framework
type EchoAdapter struct {
	handler *core.AuthHandler
}

// NewEchoAdapter creates a new Echo adapter
func NewEchoAdapter(handler *core.AuthHandler) *EchoAdapter {
	return &EchoAdapter{handler: handler}
}

// SetupRoutes registers all authentication routes with Echo
func (a *EchoAdapter) SetupRoutes(router interface{}) error {
	echoApp, ok := router.(*echo.Echo)
	if !ok {
		return &InvalidRouterError{Expected: "echo.Echo", Got: router}
	}

	// Setup Swagger if enabled
	if a.handler.Auth.Config.Swagger.Enable {
		// TODO: Add Swagger setup for Echo
	}

	// Get all routes
	allRoutes := a.handler.GetAllRoutes()

	// Create a group for the auth base path
	authGroup := echoApp.Group(a.handler.Auth.Config.BasePath)
	{
		for _, route := range allRoutes {
			// Build the middleware chain
			chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

			// Adapt the http.Handler to Echo
			echoHandler := a.adaptToEcho(chainedHandler)

			// Register the route using the correct Echo method
			switch route.Method {
			case http.MethodGet:
				authGroup.GET(route.Path, echoHandler)
			case http.MethodPost:
				authGroup.POST(route.Path, echoHandler)
			case http.MethodPut:
				authGroup.PUT(route.Path, echoHandler)
			case http.MethodDelete:
				authGroup.DELETE(route.Path, echoHandler)
			case http.MethodPatch:
				authGroup.PATCH(route.Path, echoHandler)
			default:
				authGroup.Any(route.Path, echoHandler)
			}
		}
	}

	return nil
}

// GetMiddleware returns Echo-specific middleware
func (a *EchoAdapter) GetMiddleware() interface{} {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Global middleware for Echo
			return next(c)
		}
	}
}

// GetFrameworkType returns the framework type
func (a *EchoAdapter) GetFrameworkType() core.FrameworkType {
	return core.FrameworkEcho
}

// adaptToEcho converts an http.Handler to an echo.HandlerFunc
func (a *EchoAdapter) adaptToEcho(h http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Create a custom response writer that works with Echo
		adapter := &echoResponseWriter{
			ctx: c,
		}

		h.ServeHTTP(adapter, c.Request())
		return nil
	}
}

// echoResponseWriter adapts Echo's context to http.ResponseWriter interface
type echoResponseWriter struct {
	ctx echo.Context
}

func (w *echoResponseWriter) Header() http.Header {
	return w.ctx.Response().Header()
}

func (w *echoResponseWriter) Write(data []byte) (int, error) {
	return w.ctx.Response().Write(data)
}

func (w *echoResponseWriter) WriteHeader(statusCode int) {
	w.ctx.Response().WriteHeader(statusCode)
}
