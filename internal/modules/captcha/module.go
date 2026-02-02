package captcha

import (
	"context"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/captcha/middlewares"
	"github.com/bete7512/goauth/internal/modules/captcha/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/swagger.yml
var swaggerSpec []byte

// CaptchaModule provides captcha verification middleware using external providers
// (Google reCAPTCHA v3 or Cloudflare Turnstile). Applied to specific routes only.
type CaptchaModule struct {
	deps    config.ModuleDependencies
	service *services.CaptchaService
	config  *config.CaptchaModuleConfig
}

var _ config.Module = (*CaptchaModule)(nil)

// New creates a new captcha module with the given configuration.
// If cfg is nil, captcha verification is disabled.
func New(cfg *config.CaptchaModuleConfig) *CaptchaModule {
	if cfg == nil {
		cfg = &config.CaptchaModuleConfig{}
	}
	return &CaptchaModule{
		config: cfg,
	}
}

func (m *CaptchaModule) Name() string {
	return "captcha"
}

func (m *CaptchaModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	var provider services.CaptchaProvider

	switch m.config.Provider {
	case types.CaptchaProviderGoogle:
		provider = services.NewGoogleProvider(
			m.config.SecretKey,
			m.config.ScoreThreshold,
			m.config.VerifyTimeout,
		)
		deps.Logger.Info("Captcha module initialized", "provider", "google")
	case types.CaptchaProviderCloudflare:
		provider = services.NewCloudflareProvider(
			m.config.SecretKey,
			m.config.VerifyTimeout,
		)
		deps.Logger.Info("Captcha module initialized", "provider", "cloudflare")
	default:
		deps.Logger.Info("Captcha module initialized", "provider", "none")
	}

	m.service = services.NewCaptchaService(provider)
	return nil
}

func (m *CaptchaModule) Routes() []config.RouteInfo {
	return nil
}

func (m *CaptchaModule) Middlewares() []config.MiddlewareConfig {
	if m.config.Provider == "" {
		return nil
	}
	if len(m.config.ApplyToRoutes) == 0 {
		return nil
	}

	return []config.MiddlewareConfig{
		{
			Name:        string(types.MiddlewareCaptcha),
			Middleware:  middlewares.NewCaptchaMiddleware(m.service, m.config),
			Priority:    70,
			ApplyTo:     m.config.ApplyToRoutes,
			ExcludeFrom: m.config.ExcludeRoutes,
			Global:      false,
		},
	}
}

func (m *CaptchaModule) Models() []interface{} {
	return nil
}

func (m *CaptchaModule) RegisterHooks(_ types.EventBus) error {
	return nil
}

func (m *CaptchaModule) Dependencies() []string {
	return nil
}

func (m *CaptchaModule) SwaggerSpec() []byte {
	return swaggerSpec
}

// GetSiteKey returns the public site key for frontend widget integration.
func (m *CaptchaModule) GetSiteKey() string {
	return m.config.SiteKey
}

// GetProvider returns the configured provider.
func (m *CaptchaModule) GetProvider() types.CaptchaProvider {
	return m.config.Provider
}
