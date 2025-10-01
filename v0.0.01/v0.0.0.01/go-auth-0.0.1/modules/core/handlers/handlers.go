package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/modules/core/middlewares"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreHandler struct {
	deps config.ModuleDependencies
}

func NewCoreHandler(deps config.ModuleDependencies) *CoreHandler {
	return &CoreHandler{
		deps: deps,
	}
}

func (h *CoreHandler) GetRoutes() []config.RouteInfo {
	// register routes here
	routes := []config.RouteInfo{
		{
			Path:    "/signup",
			Method:  "POST",
			Handler: h.Signup,
		},
		{
			Path:    "/login",
			Method:  "POST",
			Handler: h.Login,
		},
		{
			Path:    "/me",
			Method:  "GET",
			Handler: middlewares.AuthMiddleware(http.HandlerFunc(h.Me)).ServeHTTP,
		},
		{
			Path:    "/profile",
			Method:  "GET",
			Handler: middlewares.AuthMiddleware(http.HandlerFunc(h.Profile)).ServeHTTP,
		},
	}
	return routes
}
