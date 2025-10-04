package twofactor

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/twofactor/handlers"
	"github.com/bete7512/goauth/internal/modules/twofactor/models"
	"github.com/bete7512/goauth/internal/modules/twofactor/services"
	"github.com/bete7512/goauth/pkg/config"
)

type TwoFactorModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.TwoFactorHandler
	service  *services.TwoFactorService
	config   *TwoFactorConfig
}

type TwoFactorConfig struct {
	Issuer           string // Name shown in authenticator app
	Required         bool   // Make 2FA mandatory for all users
	BackupCodesCount int    // Number of backup codes to generate
	CodeLength       int    // Length of backup codes
}

var _ config.Module = (*TwoFactorModule)(nil)

func New(cfg ...*TwoFactorConfig) *TwoFactorModule {
	var moduleConfig *TwoFactorConfig
	if len(cfg) > 0 && cfg[0] != nil {
		moduleConfig = cfg[0]
	} else {
		moduleConfig = &TwoFactorConfig{
			Issuer:           "GoAuth",
			Required:         false,
			BackupCodesCount: 10,
			CodeLength:       8,
		}
	}

	return &TwoFactorModule{
		config: moduleConfig,
	}
}

func (m *TwoFactorModule) Name() string {
	return string(config.TwoFactorModule)
}

func (m *TwoFactorModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Initialize service
	m.service = services.NewTwoFactorService(
		deps.Storage,
		m.config.Issuer,
		m.config.BackupCodesCount,
		m.config.CodeLength,
	)

	// Initialize handlers
	m.handlers = handlers.NewTwoFactorHandler(deps, m.service)

	return nil
}

func (m *TwoFactorModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *TwoFactorModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:        "twofactor.verify",
			Middleware:  m.verify2FAMiddleware,
			Priority:    40,
			ApplyTo:     []string{"core.*", "admin.*"},
			ExcludeFrom: []string{"core.login", "core.signup", "twofactor.*"},
			Global:      false,
		},
	}
}

func (m *TwoFactorModule) Models() []interface{} {
	return []interface{}{
		&models.TwoFactor{},
		&models.BackupCode{},
	}
}

func (m *TwoFactorModule) RegisterHooks(events config.EventBus) error {
	m.deps.Logger.Info("Registering 2FA hooks")

	// Hook into after-login to check if 2FA verification is required
	// This runs synchronously - will block login if 2FA needs verification
	events.Subscribe("after:login", func(ctx context.Context, event interface{}) error {
		data, ok := event.(map[string]interface{})
		if !ok {
			return nil
		}

		userMap, ok := data["user"].(map[string]interface{})
		if !ok {
			return nil
		}

		userID, ok := userMap["id"].(string)
		if !ok {
			return nil
		}

		// Check if user has 2FA enabled
		twoFA, err := m.service.GetTwoFactorStatus(ctx, userID)
		if err != nil {
			// No 2FA configured, allow login
			return nil
		}

		if twoFA.Enabled && !twoFA.Verified {
			// User has 2FA but hasn't verified in this session
			m.deps.Logger.Info("2FA verification required", "user_id", userID)
			// In a real implementation, you'd set a flag requiring verification
			// For now, we'll just log it
		}

		return nil
	})

	// If 2FA is required for all users, hook into signup
	if m.config.Required {
		events.Subscribe("after:signup", func(ctx context.Context, event interface{}) error {
			m.deps.Logger.Info("2FA is required for all users - new user must set up 2FA")
			// In a real implementation, you might redirect to 2FA setup
			// or send an email prompting 2FA setup
			return nil
		})
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
		// TODO: Implement proper 2FA session verification
		next.ServeHTTP(w, r)
	})
}


func (m *TwoFactorModule) SwaggerSpec() []byte {
	return nil
}