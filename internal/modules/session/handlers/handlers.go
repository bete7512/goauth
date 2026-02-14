package handlers

import (
	cookie_security "github.com/bete7512/goauth/internal/security/cookie"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type SessionHandler struct {
	service services.SessionService
	deps    config.ModuleDependencies
	encoder cookie_security.CookieEncoder // nil when strategy is "database"
}

func NewSessionHandler(service services.SessionService, deps config.ModuleDependencies, encoder cookie_security.CookieEncoder) *SessionHandler {
	return &SessionHandler{
		service: service,
		deps:    deps,
		encoder: encoder,
	}
}

func (h *SessionHandler) GetRoutes() []config.RouteInfo {
	routes := []config.RouteInfo{
		{
			Name:    string(types.RouteLogin),
			Path:    "/login",
			Method:  "POST",
			Handler: h.Login,
		},
		{
			Name:        string(types.RouteLogout),
			Path:        "/logout",
			Method:      "POST",
			Handler:     h.Logout,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:    string(types.RouteRefreshToken),
			Path:    "/refresh",
			Method:  "POST",
			Handler: h.Refresh,
		},
		// Session management endpoints
		{
			Name:        "session.list",
			Path:        "/sessions",
			Method:      "GET",
			Handler:     h.ListSessions,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:        "session.get",
			Path:        "/sessions/{session_id}",
			Method:      "GET",
			Handler:     h.GetSession,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:        "session.delete",
			Path:        "/sessions/{session_id}",
			Method:      "DELETE",
			Handler:     h.DeleteSession,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:        "session.deleteAll",
			Path:        "/sessions",
			Method:      "DELETE",
			Handler:     h.DeleteAllSessions,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
	}
	return routes
}
