package core

import (
	"context"
	"fmt"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/core/handlers"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	"github.com/bete7512/goauth/internal/modules/core/models"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/security"
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

	// Get repository or return error
	getRepo := func(cfgRepo interface{}, key string) (interface{}, error) {
		if cfgRepo != nil {
			return cfgRepo, nil
		}
		repo := deps.Storage.GetRepository(key)
		if repo == nil {
			return nil, fmt.Errorf("%s repository not found", key)
		}
		return repo, nil
	}

	// Resolve repositories
	userRepoRaw, err := getRepo(m.config.UserRepository, string(config.CoreUserRepository))
	if err != nil {
		return err
	}
	userRepo, ok := userRepoRaw.(models.UserRepository)
	if !ok {
		return fmt.Errorf("user repository has invalid type")
	}

	sessionRepoRaw, err := getRepo(m.config.SessionRepository, string(config.CoreSessionRepository))
	if err != nil {
		return err
	}
	sessionRepo, ok := sessionRepoRaw.(models.SessionRepository)
	if !ok {
		return fmt.Errorf("session repository has invalid type")
	}

	tokenRepoRaw, err := getRepo(m.config.TokenRepository, string(config.CoreTokenRepository))
	if err != nil {
		return err
	}
	tokenRepo, ok := tokenRepoRaw.(models.TokenRepository)
	if !ok {
		return fmt.Errorf("token repository has invalid type")
	}

	verificationTokenRepoRaw, err := getRepo(m.config.VerificationTokenRepository, string(config.CoreVerificationTokenRepository))
	if err != nil {
		return err
	}
	verificationTokenRepo, ok := verificationTokenRepoRaw.(models.VerificationTokenRepository)
	if !ok {
		return fmt.Errorf("verification token repository has invalid type")
	}

	securityManager := security.NewSecurityManager(*m.deps.Config)
	m.handlers = handlers.NewCoreHandler(
		deps,
		core_services.NewCoreService(
			deps,
			userRepo,
			sessionRepo,
			tokenRepo,
			verificationTokenRepo,
			deps.Logger,
			securityManager,
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
