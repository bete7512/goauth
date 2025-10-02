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
	// register routes here with unique names
	routes := []config.RouteInfo{
		{
			Name:    "core.signup",
			Path:    "/signup",
			Method:  "POST",
			Handler: h.Signup,
		},
		{
			Name:    "core.login",
			Path:    "/login",
			Method:  "POST",
			Handler: h.Login,
		},
		{
			Name:    "core.me",
			Path:    "/me",
			Method:  "GET",
			Handler: middlewares.AuthMiddleware(http.HandlerFunc(h.Me)).ServeHTTP,
		},
		{
			Name:    "core.profile",
			Path:    "/profile",
			Method:  "GET",
			Handler: middlewares.AuthMiddleware(http.HandlerFunc(h.Profile)).ServeHTTP,
		},
	}
	return routes
}
