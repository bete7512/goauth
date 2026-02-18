package handlers

import (
	"github.com/bete7512/goauth/internal/modules/oauth/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// OAuthHandler handles OAuth HTTP requests
type OAuthHandler struct {
	service services.OAuthService
	deps    config.ModuleDependencies
	config  *config.OAuthModuleConfig
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(
	service services.OAuthService,
	deps config.ModuleDependencies,
	cfg *config.OAuthModuleConfig,
) *OAuthHandler {
	return &OAuthHandler{
		service: service,
		deps:    deps,
		config:  cfg,
	}
}

// GetRoutes returns the OAuth module routes
func (h *OAuthHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:    string(types.RouteOAuthLogin),
			Path:    "/oauth/{provider}",
			Method:  "GET",
			Handler: h.Login,
		},
		{
			Name:    string(types.RouteOAuthCallback),
			Path:    "/oauth/{provider}/callback",
			Method:  "GET",
			Handler: h.Callback,
		},
		{
			Name:        "oauth.unlink",
			Path:        "/oauth/{provider}",
			Method:      "DELETE",
			Handler:     h.Unlink,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:    "oauth.providers",
			Path:    "/oauth/providers",
			Method:  "GET",
			Handler: h.ListProviders,
		},
		{
			Name:        "oauth.linked",
			Path:        "/oauth/linked",
			Method:      "GET",
			Handler:     h.LinkedProviders,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
	}
}
