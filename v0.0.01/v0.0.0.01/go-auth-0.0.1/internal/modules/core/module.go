package core

import (
	"context"
	"fmt"

	_ "embed"

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
	UserRepository              models.UserRepository
	SessionRepository           models.SessionRepository
	TokenRepository             models.TokenRepository
	VerificationTokenRepository models.VerificationTokenRepository
}

//go:embed docs/swagger.yml
var swaggerSpec []byte

var _ config.Module = (*CoreModule)(nil)

func New(config *Config) *CoreModule {
	if config == nil {
		config = &Config{}
	}
	return &CoreModule{
		config: config,
	}
}

func (m *CoreModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Helper to resolve repositories
	resolveRepo := func(cfgRepo interface{}, key string, target interface{}) (interface{}, error) {
		if cfgRepo != nil {
			return cfgRepo, nil
		}
		repo := deps.Storage.GetRepository(string(key))
		if repo == nil {
			return nil, fmt.Errorf("%s repository is not found in storage", key)
		}
		return repo, nil
	}

	// Resolve repositories
	userRepo, err := resolveRepo(m.config.UserRepository, string(config.CoreUserRepository), (*models.UserRepository)(nil))
	if err != nil {
		return err
	}
	sessionRepo, err := resolveRepo(m.config.SessionRepository, string(config.CoreSessionRepository), (*models.SessionRepository)(nil))
	if err != nil {
		return err
	}
	tokenRepo, err := resolveRepo(m.config.TokenRepository, string(config.CoreTokenRepository), (*models.TokenRepository)(nil))
	if err != nil {
		return err
	}
	verificationTokenRepo, err := resolveRepo(m.config.VerificationTokenRepository, string(config.CoreVerificationTokenRepository), (*models.VerificationTokenRepository)(nil))
	if err != nil {
		return err
	}

	m.handlers = handlers.NewCoreHandler(
		deps,
		core_services.NewCoreService(
			deps,
			userRepo.(models.UserRepository),
			sessionRepo.(models.SessionRepository),
			tokenRepo.(models.TokenRepository),
			verificationTokenRepo.(models.VerificationTokenRepository),
		),
	)

	return nil
}

func (m *CoreModule) SwaggerSpec() []byte {
	return swaggerSpec
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
		&models.VerificationToken{},
		&models.Token{},
	}
	return models
}

func (m *CoreModule) RegisterHooks(events config.EventBus) error {
	events.Subscribe("before:signup", func(ctx context.Context, event interface{}) error {
		_, ok := event.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	})
	events.Subscribe("before:login", func(ctx context.Context, event interface{}) error {
		_, ok := event.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	})
	events.Subscribe("before:logout", func(ctx context.Context, event interface{}) error {
		_, ok := event.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	})
	return nil
}

func (m *CoreModule) Dependencies() []string {
	return nil
}
