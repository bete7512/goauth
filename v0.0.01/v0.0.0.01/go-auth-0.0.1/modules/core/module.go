package core

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/modules/core/handlers"
	"github.com/bete7512/goauth/modules/core/middlewares"
	"github.com/bete7512/goauth/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreModule struct {
	handlers *handlers.CoreHandler
}

var _ config.Module = (*CoreModule)(nil)

func New() *CoreModule {
	return &CoreModule{}
}

func (m *CoreModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	// Initialize handlers with dependencies
	m.handlers = handlers.NewCoreHandler(deps)
	return nil
}

func (m *CoreModule) Name() string {
	return string(config.CoreModule)
}

func (m *CoreModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *CoreModule) Middlewares() []func(http.Handler) http.Handler {
	middlewareList := []func(http.Handler) http.Handler{
		middlewares.AuthMiddleware,
	}
	return middlewareList
}

func (m *CoreModule) Models() []interface{} {
	models := []interface{}{
		&models.User{},
		&models.Session{},
	}
	return models
}

func (m *CoreModule) Hooks() config.Hooks {
	return config.Hooks{}
}

func (m *CoreModule) Dependencies() []string {
	return nil
}
