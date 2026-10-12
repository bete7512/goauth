package stateless

import (
	"context"
	_ "embed"
	"errors"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers"
	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/stateless/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

type StatelessModule struct {
	deps     config.ModuleDependencies
	service  *services.StatelessService
	handlers *handlers.StatelessHandler
	config   *config.StatelessModuleConfig
}

var _ config.Module = (*StatelessModule)(nil)

// New creates a new StatelessModule.
// Pass nil for cfg to use safe defaults (refresh token rotation enabled).
// To provide custom storage, set cfg.CustomStorage.
func New(cfg *config.StatelessModuleConfig) *StatelessModule {
	if cfg == nil {
		cfg = &config.StatelessModuleConfig{
			RefreshTokenRotation: true,
		}
	}
	snapshot := *cfg
	cfg = &snapshot
	return &StatelessModule{
		config: cfg,
	}
}

func (m *StatelessModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get core storage - use custom if provided, otherwise from main storage
	var coreStorage types.CoreStorage
	if m.config.CustomStorage != nil {
		coreStorage = m.config.CustomStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for stateless module")
	}
	// Initialize security manager
	securityManager := m.deps.SecurityManager
	if securityManager == nil {
		return errors.New("security manager is required")
	}

	// Initialize handlers with all dependencies
	m.service = services.NewStatelessService(
		m.deps,
		coreStorage.Users(),
		coreStorage.Tokens(),
		m.deps.Logger,
		securityManager,
		m.config,
	)
	m.handlers = handlers.NewStatelessHandler(
		m.service,
		m.deps,
	)

	return nil
}

func (m *StatelessModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *StatelessModule) Name() string {
	return string(types.StatelessModule)
}

func (m *StatelessModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *StatelessModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

func (m *StatelessModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *StatelessModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

func (m *StatelessModule) Migrations() types.ModuleMigrations {
	return types.ModuleMigrations{}
}

func (m *StatelessModule) StorageBindings() config.StorageBindings {
	return config.StorageBindings{Core: m.config.CustomStorage}
}

func (m *StatelessModule) SignIn(ctx context.Context, request types.SignInRequest) (types.AuthenticationResult, error) {
	input := &dto.LoginRequest{Email: request.Email, Username: request.Username, Password: request.Password}
	if err := input.Validate(); err != nil {
		return types.AuthenticationResult{Status: types.Denied}, err
	}
	if m.deps.Events != nil {
		if err := m.deps.Events.EmitSync(ctx, types.EventBeforeLogin, &types.BeforeHookData{Body: *input, Metadata: request.Metadata}); err != nil {
			return types.AuthenticationResult{Status: types.Denied}, types.NewForbiddenError().Wrap(err)
		}
	}
	response, err := m.service.Login(ctx, input)
	if err != nil {
		return types.AuthenticationResult{Status: types.Denied}, err
	}
	result := types.AuthenticationResult{Status: types.Authenticated, Challenges: response.Challenges, Data: response.Data, ExpiresIn: response.ExpiresIn}
	if len(result.Challenges) > 0 {
		result.Status = types.ChallengeRequired
	}
	if response.User != nil {
		result.UserID = response.User.ID
	}
	if response.AccessToken != nil {
		result.AccessToken = *response.AccessToken
	}
	if response.RefreshToken != nil {
		result.RefreshToken = *response.RefreshToken
	}
	return result, nil
}
