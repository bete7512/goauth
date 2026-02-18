package chiadapter

import (
	"net/http"
	"regexp"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/go-chi/chi/v5"
)

// RouteSource provides routes for registration. *auth.Auth satisfies this interface.
type RouteSource interface {
	Routes() []config.RouteInfo
}

// Register adds all auth routes to a Chi router.
// Chi uses {param} syntax natively, so no path conversion is needed.
// Bridges path parameters from chi.URLParam() to r.SetPathValue()
// so that handlers using r.PathValue() work correctly.
func Register(router chi.Router, auth RouteSource) {
	for _, route := range auth.Routes() {
		paramNames := extractParams(route.Path)
		handler := route.Handler
		router.Method(route.Method, route.Path, wrapHandler(handler, paramNames))
	}
}

// wrapHandler creates an http.Handler that bridges path parameters from
// Chi's URLParam to net/http's SetPathValue, then calls the original handler.
func wrapHandler(handler http.HandlerFunc, paramNames []string) http.HandlerFunc {
	if len(paramNames) == 0 {
		return handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, name := range paramNames {
			r.SetPathValue(name, chi.URLParam(r, name))
		}
		handler(w, r)
	}
}

var pathParamRegex = regexp.MustCompile(`\{(\w+)\}`)

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
