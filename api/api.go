package api

import (
	"fmt"

	"github.com/bete7512/goauth/api/core"
	"github.com/bete7512/goauth/api/frameworks"
	"github.com/bete7512/goauth/config"
)

// AuthAPI provides a unified interface for authentication across different frameworks
type AuthAPI struct {
	handler *core.AuthHandler
}

// NewAuthAPI creates a new AuthAPI instance
func NewAuthAPI(auth *config.Auth) *AuthAPI {
	return &AuthAPI{
		handler: core.NewAuthHandler(auth),
		
	}
}

// SetupRoutes configures authentication routes for the specified framework
func (api *AuthAPI) SetupRoutes(frameworkType core.FrameworkType, router interface{}) error {
	adapter, err := api.createAdapter(frameworkType)
	if err != nil {
		return fmt.Errorf("failed to create adapter: %w", err)
	}

	return adapter.SetupRoutes(router)
}

// GetMiddleware returns framework-specific middleware
func (api *AuthAPI) GetMiddleware(frameworkType core.FrameworkType) (interface{}, error) {
	adapter, err := api.createAdapter(frameworkType)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}

	return adapter.GetMiddleware(), nil
}

// GetSupportedFrameworks returns a list of all supported frameworks
func (api *AuthAPI) GetSupportedFrameworks() []core.FrameworkType {
	return []core.FrameworkType{
		core.FrameworkGin,
		core.FrameworkChi,
		core.FrameworkEcho,
		core.FrameworkFiber,
		core.FrameworkGorillaMux,
		core.FrameworkStandard,
	}
}

// GetRoutes returns all available routes for inspection
func (api *AuthAPI) GetRoutes() []core.RouteDefinition {
	return api.handler.GetAllRoutes()
}

// GetCoreRoutes returns only the core authentication routes
func (api *AuthAPI) GetCoreRoutes() []core.RouteDefinition {
	return api.handler.GetCoreRoutes()
}

// GetOAuthRoutes returns only the OAuth provider routes
func (api *AuthAPI) GetOAuthRoutes() []core.RouteDefinition {
	return api.handler.GetOAuthRoutes()
}

// createAdapter creates a framework-specific adapter
func (api *AuthAPI) createAdapter(frameworkType core.FrameworkType) (core.FrameworkAdapter, error) {
	switch frameworkType {
	case core.FrameworkGin:
		return frameworks.NewGinAdapter(api.handler), nil
	case core.FrameworkChi:
		return frameworks.NewChiAdapter(api.handler), nil
	case core.FrameworkEcho:
		return frameworks.NewEchoAdapter(api.handler), nil
	case core.FrameworkFiber:
		return frameworks.NewFiberAdapter(api.handler), nil
	case core.FrameworkGorillaMux:
		return frameworks.NewGorillaMuxAdapter(api.handler), nil
	case core.FrameworkStandard:
		return frameworks.NewStandardAdapter(api.handler), nil
	default:
		return nil, fmt.Errorf("unsupported framework: %s", frameworkType)
	}
}

// Convenience functions for each framework

// SetupGinRoutes is a convenience function for Gin
func (api *AuthAPI) SetupGinRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkGin, router)
}

// SetupChiRoutes is a convenience function for Chi
func (api *AuthAPI) SetupChiRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkChi, router)
}

// SetupEchoRoutes is a convenience function for Echo
func (api *AuthAPI) SetupEchoRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkEcho, router)
}

// SetupFiberRoutes is a convenience function for Fiber
func (api *AuthAPI) SetupFiberRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkFiber, router)
}

// SetupGorillaMuxRoutes is a convenience function for Gorilla Mux
func (api *AuthAPI) SetupGorillaMuxRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkGorillaMux, router)
}

// SetupStandardRoutes is a convenience function for Standard HTTP
func (api *AuthAPI) SetupStandardRoutes(router interface{}) error {
	return api.SetupRoutes(core.FrameworkStandard, router)
}
