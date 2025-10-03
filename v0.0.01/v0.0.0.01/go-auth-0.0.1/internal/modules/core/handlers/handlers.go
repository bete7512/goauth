package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreHandler struct {
	deps        config.ModuleDependencies
	CoreService *core_services.CoreService
}

func NewCoreHandler(deps config.ModuleDependencies, coreService *core_services.CoreService) *CoreHandler {
	return &CoreHandler{
		deps:        deps,
		CoreService: coreService,
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
