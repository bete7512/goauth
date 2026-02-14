package stdhttp

import (
	"net/http"

	"github.com/bete7512/goauth/pkg/config"
)

// RouteSource provides routes for registration. *auth.Auth satisfies this interface.
type RouteSource interface {
	Routes() []config.RouteInfo
}

// Register adds all auth routes to a standard library ServeMux.
// Uses Go 1.22+ method-based routing pattern: "METHOD PATH".
func Register(mux *http.ServeMux, auth RouteSource) http.Handler {
	for _, route := range auth.Routes() {
		mux.HandleFunc(route.Method+" "+route.Path, route.Handler)
	}
	return mux
}
