package handlers

import (
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type SessionHandler struct {
	SessionService *services.SessionService
	deps           config.ModuleDependencies
}

func NewSessionHandler(sessionService *services.SessionService, deps config.ModuleDependencies) *SessionHandler {
	return &SessionHandler{
		SessionService: sessionService,
		deps:           deps,
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
			Middlewares: []string{string(types.MiddlewareAuth)},
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
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        "session.get",
			Path:        "/sessions/{id}",
			Method:      "GET",
			Handler:     h.GetSession,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        "session.delete",
			Path:        "/sessions/{id}",
			Method:      "DELETE",
			Handler:     h.DeleteSession,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        "session.deleteAll",
			Path:        "/sessions",
			Method:      "DELETE",
			Handler:     h.DeleteAllSessions,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
	}
	return routes
}
