package twofactor

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/twofactor/handlers"
	"github.com/bete7512/goauth/internal/modules/twofactor/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
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

	// Initialize service
	m.service = services.NewTwoFactorService(
		deps,
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
	m.deps.Logger.Info("Registering 2FA hooks")

	// Hook into password verification to intercept login flow
	// This runs SYNCHRONOUSLY to allow us to prevent token issuance if 2FA is required
	events.Subscribe(types.EventAfterPasswordVerified, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		// Extract user from event
		data, ok := types.EventDataAs[*types.PasswordVerifiedEventData](event)
		if !ok {
			m.deps.Logger.Warn("Failed to extract PasswordVerifiedEventData")
			return nil // Don't block login on event parsing failure
		}

		// Check if user has 2FA enabled
		tfConfig, authErr := m.service.GetTwoFactorConfig(ctx, data.User.ID)
		if authErr != nil || tfConfig == nil || !tfConfig.Enabled {
			// No 2FA configured or not enabled - allow normal login
			return nil
		}

		m.deps.Logger.Info("2FA required for user", "user_id", data.User.ID)

		// Generate temporary token for 2FA flow
		tempToken, err := m.generateTempToken(data.User.ID)
		if err != nil {
			m.deps.Logger.Error("Failed to generate temp 2FA token", "error", err)
			// Fail gracefully - allow login without 2FA
			return nil
		}

		// Return special error to interrupt login flow
		// Core module will catch this and return the challenge to the user
		return types.NewTwoFactorRequiredError(map[string]any{
			"requires_2fa": true,
			"temp_token":   tempToken,
			"user_id":      data.User.ID,
			"message":      "Two-factor authentication required. Please provide your 2FA code.",
		})
	}))

	// If 2FA is required for all users, hook into signup
	if m.config.Required {
		events.Subscribe(types.EventAfterSignup, types.EventHandler(func(ctx context.Context, event *types.Event) error {
			m.deps.Logger.Info("2FA is required for all users - new user must set up 2FA")
			// TODO: Could send email prompting 2FA setup
			return nil
		}))
	}

	return nil
}

func (m *TwoFactorModule) Dependencies() []string {
	return []string{"core"}
}

// generateTempToken creates a short-lived JWT for pending 2FA verification
func (m *TwoFactorModule) generateTempToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "2fa_pending",
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(m.deps.Config.Security.JwtSecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign temp token: %w", err)
	}

	return tokenString, nil
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
	result := types.ModuleMigrations{}
	for _, d := range []types.DialectType{types.DialectTypePostgres, types.DialectTypeMysql, types.DialectTypeSqlite} {
		up, _ := migrationFS.ReadFile("migrations/" + string(d) + "/up.sql")
		down, _ := migrationFS.ReadFile("migrations/" + string(d) + "/down.sql")
		if len(up) > 0 {
			result[d] = types.MigrationFiles{Up: up, Down: down}
		}
	}
	return result
}
