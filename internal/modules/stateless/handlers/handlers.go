package handlers

import (
	"github.com/bete7512/goauth/internal/modules/stateless/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type StatelessHandler struct {
	StatelessService *services.StatelessService
	deps             config.ModuleDependencies
}

func NewStatelessHandler(statelessService *services.StatelessService, deps config.ModuleDependencies) *StatelessHandler {
	return &StatelessHandler{
		StatelessService: statelessService,
		deps:             deps,
	}
}

func (h *StatelessHandler) GetRoutes() []config.RouteInfo {
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
	}
	return routes
}
