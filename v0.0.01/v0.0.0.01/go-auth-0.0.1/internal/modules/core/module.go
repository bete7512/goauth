package core

import (
	"context"
	"fmt"
	"log"

	"github.com/bete7512/goauth/internal/modules/core/handlers"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	"github.com/bete7512/goauth/internal/modules/core/models"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.CoreHandler
	config   *Config
}
type Config struct {
	UserRepository    models.UserRepository
	SessionRepository models.SessionRepository
}

var _ config.Module = (*CoreModule)(nil)

func New(config *Config) *CoreModule {
	coreModule := &CoreModule{}
	if config.UserRepository != nil || config.SessionRepository != nil {
		if err := coreModule.ValidateRepositories(); err != nil {
			log.Println("core module repositories are not valid: %v", err.Error())
		}
	}
	coreModule.config = config
	coreModule.handlers = handlers.NewCoreHandler(coreModule.deps, core_services.NewCoreService(coreModule.deps, config.UserRepository, config.SessionRepository))
	return coreModule
}

func (m *CoreModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	if m.config.UserRepository == nil || m.config.SessionRepository == nil {
		deps.Repositories[config.CoreUserRepository] = m.config.UserRepository
		deps.Repositories[config.CoreSessionRepository] = m.config.SessionRepository
		m.handlers = handlers.NewCoreHandler(deps, core_services.NewCoreService(deps, m.deps.Repositories[config.CoreUserRepository].(models.UserRepository), m.deps.Repositories[config.CoreSessionRepository].(models.SessionRepository)))
	}
	return nil
}
func (m *CoreModule) ValidateRepositories() error {
	if _, ok := m.deps.Repositories[config.CoreUserRepository]; !ok {
		return fmt.Errorf("core.user repository is required")
	}
	if _, ok := m.deps.Repositories[config.CoreSessionRepository]; !ok {
		return fmt.Errorf("core.session repository is required")
	}
	// check also if it is of type UserRepository and SessionRepository
	if _, ok := m.deps.Repositories[config.CoreUserRepository].(models.UserRepository); !ok {
		return fmt.Errorf("core.user repository is not of type UserRepository")
	}
	if _, ok := m.deps.Repositories[config.CoreSessionRepository].(models.SessionRepository); !ok {
		return fmt.Errorf("core.session repository is not of type SessionRepository")
	}

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

func (m *CoreModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       "core.auth",
			Middleware: middlewares.AuthMiddleware,
			Priority:   50,
			ApplyTo:    []string{"core.me", "core.profile", "core.logout"},
			Global:     false,
		},
	}
}

func (m *CoreModule) Models() []interface{} {
	models := []interface{}{
		&models.User{},
		&models.Session{},
	}
	return models
}

func (m *CoreModule) RegisterHooks(events config.EventBus) error {
	// Register event handlers for core module
	// Example: events.Subscribe("before:signup", m.onBeforeSignup)
	return nil
}

func (m *CoreModule) Dependencies() []string {
	return nil
}
