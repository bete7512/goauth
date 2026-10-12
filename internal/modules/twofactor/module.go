package twofactor

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"slices"

	"github.com/bete7512/goauth/internal/modules/twofactor/handlers"
	"github.com/bete7512/goauth/internal/modules/twofactor/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type TwoFactorModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.TwoFactorHandler
	service  services.TwoFactorService
	config   *config.TwoFactorConfig
}

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed migrations
	migrationFS embed.FS
)
var _ config.Module = (*TwoFactorModule)(nil)

func New(cfg ...*config.TwoFactorConfig) *TwoFactorModule {
	var moduleConfig *config.TwoFactorConfig
	if len(cfg) > 0 && cfg[0] != nil {
		moduleConfig = cfg[0]
	} else {
		moduleConfig = &config.TwoFactorConfig{}
	}

	snapshot := *moduleConfig
	moduleConfig = &snapshot
	// Apply defaults for any zero values (handles partial configs)
	if moduleConfig.Issuer == "" {
		moduleConfig.Issuer = "GoAuth"
	}
	if moduleConfig.BackupCodesCount <= 0 {
		moduleConfig.BackupCodesCount = 10
	}
	if moduleConfig.CodeLength <= 0 {
		moduleConfig.CodeLength = 8
	}

	return &TwoFactorModule{
		config: moduleConfig,
	}
}

func (m *TwoFactorModule) Name() string {
	return string(types.TwoFactorModule)
}

func (m *TwoFactorModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	if deps.Storage == nil || deps.Storage.TwoFactorAuth() == nil || deps.Storage.Core() == nil {
		return fmt.Errorf("twofactor requires core and two-factor storage")
	}

	// Initialize service
	svc := services.NewTwoFactorService(
		deps,
		m.config.Issuer,
		m.config.BackupCodesCount,
		m.config.CodeLength,
	)
	m.service = svc

	// Initialize handlers
	m.handlers = handlers.NewTwoFactorHandler(deps, m.service)

	// Register auth interceptor for 2FA challenge
	deps.AuthInterceptors.Register("twofactor", func(ctx context.Context, params *types.InterceptParams) (*types.InterceptResult, error) {

		tfConfig, authErr := m.service.GetTwoFactorConfig(ctx, params.User.ID)
		if authErr != nil && authErr.Code != types.ErrTwoFactorNotFound {
			return nil, authErr
		}
		if tfConfig == nil || !tfConfig.Enabled {
			if m.config.Required {
				return nil, fmt.Errorf("two-factor enrollment required")
			}
			return &types.InterceptResult{}, nil
		}

		if params.Phase != types.PhaseLogin && (slices.Contains(params.VerifiedMethods, "2fa") || slices.Contains(params.VerifiedMethods, "mfa")) {
			return &types.InterceptResult{}, nil
		}
		m.deps.Logger.Info("2FA required for user", "user_id", params.User.ID)

		return &types.InterceptResult{
			Challenge: &types.LoginChallenge{
				Type: types.ChallengeTwoFactor,
				Data: map[string]interface{}{
					"requires_2fa": true,
					"user_id":      params.User.ID,
					"message":      "Two-factor authentication required. Please provide your 2FA code.",
				},
			},
		}, nil
	}, 100) // High priority — 2FA challenges checked first

	return nil
}

func (m *TwoFactorModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return []config.RouteInfo{
		{
			Name:        "twofactor.setup",
			Path:        "/2fa/setup",
			Method:      http.MethodPost,
			Handler:     m.handlers.SetupHandler,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        "twofactor.verify",
			Path:        "/2fa/verify",
			Method:      http.MethodPost,
			Handler:     m.handlers.VerifyHandler,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        "twofactor.disable",
			Path:        "/2fa/disable",
			Method:      http.MethodPost,
			Handler:     m.handlers.DisableHandler,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        "twofactor.status",
			Path:        "/2fa/status",
			Method:      http.MethodGet,
			Handler:     m.handlers.StatusHandler,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			// No auth middleware - uses temp_token from 2FA challenge instead
			Name:    "twofactor.verify-login",
			Path:    "/2fa/verify-login",
			Method:  http.MethodPost,
			Handler: m.handlers.VerifyLoginHandler,
		},
	}
}

func (m *TwoFactorModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:        "twofactor.verify",
			Middleware:  m.verify2FAMiddleware,
			Priority:    40,
			ApplyTo:     []types.RouteName{"core.*", "admin.*"},
			ExcludeFrom: []types.RouteName{types.RouteLogin, types.RouteSignup, "twofactor.*"},
			Global:      false,
		},
	}
}

func (m *TwoFactorModule) RegisterHooks(events types.EventBus) error {
	// 2FA login interception is now handled via AuthInterceptors (registered in Init).
	// Only keep event-based hooks for non-login flows.

	if m.config.Required {
		events.Subscribe(types.EventAfterSignup, types.EventHandler(func(ctx context.Context, event *types.Event) error {
			m.deps.Logger.Info("2FA is required for all users - new user must set up 2FA")
			return nil
		}))
	}

	return nil
}

func (m *TwoFactorModule) Dependencies() []string {
	return []string{"core"}
}

// verify2FAMiddleware checks if user has completed 2FA verification
func (m *TwoFactorModule) verify2FAMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user has 2FA enabled and verified in current session
		// If not verified, require verification

		// For now, just pass through
		// TODO: Implement proper 2FA session verification (step-up authentication)
		next.ServeHTTP(w, r)
	})
}

func (m *TwoFactorModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *TwoFactorModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}
