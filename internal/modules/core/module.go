package core

import (
	"context"
	"fmt"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/core/handlers"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	"github.com/bete7512/goauth/internal/modules/core/models"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	notification_models "github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type CoreModule struct {
	deps               config.ModuleDependencies
	handlers           *handlers.CoreHandler
	customRepositories *CustomRepositories
	config             *config.CoreConfig
}
type CustomRepositories struct {
	UserRepository                  models.UserRepository
	UserExtendedAttributeRepository models.ExtendedAttributeRepository
	SessionRepository               models.SessionRepository
	TokenRepository                 models.TokenRepository
	VerificationTokenRepository     notification_models.VerificationTokenRepository
}

//go:embed docs/swagger.yml
var swaggerSpec []byte

var _ config.Module = (*CoreModule)(nil)

func New(cfg *config.CoreConfig, customRepositories *CustomRepositories) *CoreModule {
	if cfg == nil {
		cfg = &config.CoreConfig{}
	}
	return &CoreModule{
		config:             cfg,
		customRepositories: customRepositories,
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
	userRepoRaw, err := getRepo(m.customRepositories.UserRepository, string(types.CoreUserRepository))
	if err != nil {
		return err
	}
	userRepo, ok := userRepoRaw.(models.UserRepository)
	if !ok {
		return fmt.Errorf("user repository has invalid type")
	}

	sessionRepoRaw, err := getRepo(m.customRepositories.SessionRepository, string(types.CoreSessionRepository))
	if err != nil {
		return err
	}
	sessionRepo, ok := sessionRepoRaw.(models.SessionRepository)
	if !ok {
		return fmt.Errorf("session repository has invalid type")
	}

	tokenRepoRaw, err := getRepo(m.customRepositories.TokenRepository, string(types.CoreTokenRepository))
	if err != nil {
		return err
	}
	tokenRepo, ok := tokenRepoRaw.(models.TokenRepository)
	if !ok {
		return fmt.Errorf("token repository has invalid type")
	}

	verificationTokenRepoRaw, err := getRepo(m.customRepositories.VerificationTokenRepository, string(types.CoreVerificationTokenRepository))
	if err != nil {
		return err
	}
	verificationTokenRepo, ok := verificationTokenRepoRaw.(notification_models.VerificationTokenRepository)
	if !ok {
		return fmt.Errorf("verification token repository has invalid type")
	}
	userAttrRepoRaw, err := getRepo(m.customRepositories.UserExtendedAttributeRepository, string(types.CoreUserExtendedAttributeRepository))
	if err != nil {
		return err
	}
	userAttrRepo, ok := userAttrRepoRaw.(models.ExtendedAttributeRepository)
	if !ok {
		return fmt.Errorf("user attribute repository has invalid type")
	}
	if m.deps.Config.Core != nil {
		m.config = &config.CoreConfig{
			RequireEmailVerification: m.deps.Config.Core.RequireEmailVerification,
			RequirePhoneVerification: m.deps.Config.Core.RequirePhoneVerification,
			RequireUserName:          m.deps.Config.Core.RequireUserName,
			RequirePhoneNumber:       m.deps.Config.Core.RequirePhoneNumber,
		}
	}

	securityManager := security.NewSecurityManager(m.deps.Config.Security)
	deps.SecurityManager = securityManager
	m.handlers = handlers.NewCoreHandler(
		core_services.NewCoreService(
			deps,
			userRepo,
			userAttrRepo,
			sessionRepo,
			tokenRepo,
			verificationTokenRepo,
			deps.Logger,
			securityManager,
			m.config,
		),
		m.deps,
	)

	return nil
}
func (m *CoreModule) SwaggerSpec() []byte {
	return swaggerSpec
}

func (m *CoreModule) Name() string {
	return string(types.CoreModule)
}

func (m *CoreModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *CoreModule) Middlewares() []config.MiddlewareConfig {
	authMiddleware := middlewares.NewAuthMiddleware(m.deps.Config, m.handlers.CoreService.SecurityManager)
	return []config.MiddlewareConfig{
		{
			Name:       "core.auth",
			Middleware: authMiddleware.AuthMiddleware,
			Priority:   50,
			ApplyTo:    []string{"core.me", "core.profile", "core.logout"},
			Global:     false,
		},
	}
}

func (m *CoreModule) Models() []interface{} {
	models := []interface{}{
		&models.User{},
		&models.ExtendedAttributes{},
		&models.Session{},
		&models.Token{},
	}
	return models
}

func (m *CoreModule) RegisterHooks(events types.EventBus) error {
	events.Subscribe(types.EventBeforeSignup, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		_, ok := event.Data.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	}))
	events.Subscribe(types.EventBeforeLogin, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		_, ok := event.Data.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	}))
	events.Subscribe(types.EventBeforeLogout, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		_, ok := event.Data.(map[string]interface{})
		if !ok {
			return nil
		}
		return nil
	}))
	return nil
}

func (m *CoreModule) Dependencies() []string {
	return nil
}
