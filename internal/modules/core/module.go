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

	// Resolve repositories
	userRepo, err := m.resolveUserRepository()
	if err != nil {
		return err
	}

	sessionRepo, err := m.resolveSessionRepository()
	if err != nil {
		return err
	}

	tokenRepo, err := m.resolveTokenRepository()
	if err != nil {
		return err
	}

	verificationTokenRepo, err := m.resolveVerificationTokenRepository()
	if err != nil {
		return err
	}

	userAttrRepo, err := m.resolveUserAttributeRepository()
	if err != nil {
		return err
	}

	// Update config from dependencies if provided
	m.updateConfigFromDeps()

	// Initialize security manager
	securityManager := security.NewSecurityManager(m.deps.Config.Security)
	m.deps.SecurityManager = securityManager

	// Initialize handlers with all dependencies
	m.handlers = handlers.NewCoreHandler(
		core_services.NewCoreService(
			m.deps,
			userRepo,
			userAttrRepo,
			sessionRepo,
			tokenRepo,
			verificationTokenRepo,
			m.deps.Logger,
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
	authMiddleware := middlewares.NewAuthMiddleware(m.deps.Config, m.deps.SecurityManager)
	return []config.MiddlewareConfig{
		{
			Name:       string(types.MiddlewareAuth),
			Middleware: authMiddleware.AuthMiddleware,
			Priority:   50,
			ApplyTo:    []string{},
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
	// register hooks here
	return nil
}

func (m *CoreModule) Dependencies() []string {
	return nil
}

// Private helper functions for repository resolution

func (m *CoreModule) getRepositoryOrDefault(customRepo interface{}, repositoryKey string) (interface{}, error) {
	if customRepo != nil {
		return customRepo, nil
	}
	repo := m.deps.Storage.GetRepository(repositoryKey)
	if repo == nil {
		return nil, fmt.Errorf("%s repository not found", repositoryKey)
	}
	return repo, nil
}

func (m *CoreModule) resolveUserRepository() (models.UserRepository, error) {
	repoRaw, err := m.getRepositoryOrDefault(m.customRepositories.UserRepository, string(types.CoreUserRepository))
	if err != nil {
		return nil, err
	}
	repo, ok := repoRaw.(models.UserRepository)
	if !ok {
		return nil, fmt.Errorf("user repository has invalid type")
	}
	return repo, nil
}

func (m *CoreModule) resolveSessionRepository() (models.SessionRepository, error) {
	repoRaw, err := m.getRepositoryOrDefault(m.customRepositories.SessionRepository, string(types.CoreSessionRepository))
	if err != nil {
		return nil, err
	}
	repo, ok := repoRaw.(models.SessionRepository)
	if !ok {
		return nil, fmt.Errorf("session repository has invalid type")
	}
	return repo, nil
}

func (m *CoreModule) resolveTokenRepository() (models.TokenRepository, error) {
	repoRaw, err := m.getRepositoryOrDefault(m.customRepositories.TokenRepository, string(types.CoreTokenRepository))
	if err != nil {
		return nil, err
	}
	repo, ok := repoRaw.(models.TokenRepository)
	if !ok {
		return nil, fmt.Errorf("token repository has invalid type")
	}
	return repo, nil
}

func (m *CoreModule) resolveVerificationTokenRepository() (notification_models.VerificationTokenRepository, error) {
	repoRaw, err := m.getRepositoryOrDefault(m.customRepositories.VerificationTokenRepository, string(types.CoreVerificationTokenRepository))
	if err != nil {
		return nil, err
	}
	repo, ok := repoRaw.(notification_models.VerificationTokenRepository)
	if !ok {
		return nil, fmt.Errorf("verification token repository has invalid type")
	}
	return repo, nil
}

func (m *CoreModule) resolveUserAttributeRepository() (models.ExtendedAttributeRepository, error) {
	repoRaw, err := m.getRepositoryOrDefault(m.customRepositories.UserExtendedAttributeRepository, string(types.CoreUserExtendedAttributeRepository))
	if err != nil {
		return nil, err
	}
	repo, ok := repoRaw.(models.ExtendedAttributeRepository)
	if !ok {
		return nil, fmt.Errorf("user attribute repository has invalid type")
	}
	return repo, nil
}

func (m *CoreModule) updateConfigFromDeps() {
	if m.deps.Config.Core != nil {
		m.config = &config.CoreConfig{
			RequireEmailVerification: m.deps.Config.Core.RequireEmailVerification,
			RequirePhoneVerification: m.deps.Config.Core.RequirePhoneVerification,
			RequireUserName:          m.deps.Config.Core.RequireUserName,
			RequirePhoneNumber:       m.deps.Config.Core.RequirePhoneNumber,
		}
	}
}
