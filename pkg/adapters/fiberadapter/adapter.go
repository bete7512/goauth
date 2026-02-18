package fiberadapter

import (
	"net/http"
	"regexp"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

// RouteSource provides routes for registration. *auth.Auth satisfies this interface.
type RouteSource interface {
	Routes() []config.RouteInfo
}

// Register adds all auth routes to a Fiber app.
// Converts {param} path syntax to :param and bridges path parameters
// so that handlers using r.PathValue() work correctly.
func Register(app *fiber.App, auth RouteSource) {
	for _, route := range auth.Routes() {
		paramNames := extractParams(route.Path)
		path := toColonParams(route.Path)
		handler := route.Handler
		app.Add(route.Method, path, wrapHandler(handler, paramNames))
	}
}

// wrapHandler creates a Fiber handler that converts the fasthttp request to
// a net/http request, bridges path parameters, and calls the original handler.
func wrapHandler(handler http.HandlerFunc, paramNames []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var r http.Request
		if err := fasthttpadaptor.ConvertRequest(c.Context(), &r, true); err != nil {
			return fiber.ErrInternalServerError
		}
		for _, name := range paramNames {
			r.SetPathValue(name, c.Params(name))
		}
		w := &responseWriter{ctx: c}
		handler(w, &r)
		return nil
	}
}

var pathParamRegex = regexp.MustCompile(`\{(\w+)\}`)

// toColonParams converts "/sessions/{id}" to "/sessions/:id".
func toColonParams(path string) string {
	return pathParamRegex.ReplaceAllString(path, ":$1")
}

// extractParams returns parameter names from a path pattern.
// extractParams("/users/{id}/sessions/{sid}") → ["id", "sid"]
func extractParams(path string) []string {
	matches := pathParamRegex.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return nil
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m[1]
	}
	return names
}

// responseWriter adapts Fiber's context to http.ResponseWriter.
type responseWriter struct {
	ctx        *fiber.Ctx
	statusCode int
	header     http.Header
	written    bool
}

func (w *responseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.written = true
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	// Apply headers to Fiber context
	for key, values := range w.header {
		for _, value := range values {
			w.ctx.Set(key, value)
		}
	}
	w.ctx.Status(w.statusCode)
	return w.ctx.Write(data)
}
