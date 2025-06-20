package frameworks

import (
	"bytes"
	"net/http"

	"github.com/bete7512/goauth/api/core"
	"github.com/gofiber/fiber/v2"
)

// FiberAdapter adapts the core authentication routes to the Fiber framework
type FiberAdapter struct {
	handler *core.AuthHandler
}

// NewFiberAdapter creates a new Fiber adapter
func NewFiberAdapter(handler *core.AuthHandler) *FiberAdapter {
	return &FiberAdapter{handler: handler}
}

// SetupRoutes registers all authentication routes with Fiber
func (a *FiberAdapter) SetupRoutes(router interface{}) error {
	fiberApp, ok := router.(*fiber.App)
	if !ok {
		return &InvalidRouterError{Expected: "fiber.App", Got: router}
	}

	// Setup Swagger if enabled
	if a.handler.Auth.Config.Swagger.Enable {
		// TODO: Add Swagger setup for Fiber
	}

	// Get all routes
	allRoutes := a.handler.GetAllRoutes()

	// Create a group for the auth base path
	authGroup := fiberApp.Group(a.handler.Auth.Config.BasePath)
	{
		for _, route := range allRoutes {
			// Build the middleware chain
			chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

			// Adapt the http.Handler to Fiber
			fiberHandler := a.adaptToFiber(chainedHandler)

			// Register the route using the correct Fiber method
			switch route.Method {
			case http.MethodGet:
				authGroup.Get(route.Path, fiberHandler)
			case http.MethodPost:
				authGroup.Post(route.Path, fiberHandler)
			case http.MethodPut:
				authGroup.Put(route.Path, fiberHandler)
			case http.MethodDelete:
				authGroup.Delete(route.Path, fiberHandler)
			case http.MethodPatch:
				authGroup.Patch(route.Path, fiberHandler)
			default:
				authGroup.All(route.Path, fiberHandler)
			}
		}
	}

	return nil
}

// GetMiddleware returns Fiber-specific middleware
func (a *FiberAdapter) GetMiddleware() interface{} {
	return func(c *fiber.Ctx) error {
		// Global middleware for Fiber
		return c.Next()
	}
}

// GetFrameworkType returns the framework type
func (a *FiberAdapter) GetFrameworkType() core.FrameworkType {
	return core.FrameworkFiber
}

// adaptToFiber converts an http.Handler to a fiber.Handler
func (a *FiberAdapter) adaptToFiber(h http.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Read the request body
		body := c.Body()

		// Create a custom request/response adapter for Fiber
		adapter := &fiberResponseWriter{
			ctx: c,
		}

		// Convert fasthttp request to http.Request
		httpReq, err := http.NewRequest(
			string(c.Method()),
			c.OriginalURL(),
			bytes.NewReader(body), // ✅ Include the actual body
		)
		if err != nil {
			return err
		}

		// Copy headers
		c.Request().Header.VisitAll(func(key, value []byte) {
			httpReq.Header.Set(string(key), string(value))
		})

		// Copy query parameters
		httpReq.URL.RawQuery = string(c.Request().URI().QueryString())

		// Set content length
		httpReq.ContentLength = int64(len(body))

		// Set remote address
		httpReq.RemoteAddr = c.IP()

		h.ServeHTTP(adapter, httpReq)
		return nil
	}
}

// fiberResponseWriter adapts Fiber's context to http.ResponseWriter interface
type fiberResponseWriter struct {
	ctx *fiber.Ctx
}

func (w *fiberResponseWriter) Header() http.Header {
	// Return a header map that can be modified
	headers := make(http.Header)
	w.ctx.Context().Request.Header.VisitAll(func(key, value []byte) {
		headers.Set(string(key), string(value))
	})
	return headers
}

func (w *fiberResponseWriter) Write(data []byte) (int, error) {
	return w.ctx.Write(data)
}

func (w *fiberResponseWriter) WriteHeader(statusCode int) {
	w.ctx.Status(statusCode)
}
