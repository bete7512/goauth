package ginadapter

import (
	"net/http"
	"regexp"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/gin-gonic/gin"
)

// RouteSource provides routes for registration. *auth.Auth satisfies this interface.
type RouteSource interface {
	Routes() []config.RouteInfo
}

// Register adds all auth routes to a Gin router.
// Converts {param} path syntax to :param and bridges path parameters
// so that handlers using r.PathValue() work correctly.
func Register(router gin.IRouter, auth RouteSource) {
	for _, route := range auth.Routes() {
		paramNames := extractParams(route.Path)
		path := toColonParams(route.Path)
		handler := route.Handler
		router.Handle(route.Method, path, wrapHandler(handler, paramNames))
	}
}

// wrapHandler creates a Gin handler that bridges path parameters from
// Gin's c.Param() to net/http's r.SetPathValue(), then calls the original handler.
func wrapHandler(handler http.HandlerFunc, paramNames []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, name := range paramNames {
			c.Request.SetPathValue(name, c.Param(name))
		}
		handler(c.Writer, c.Request)
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
