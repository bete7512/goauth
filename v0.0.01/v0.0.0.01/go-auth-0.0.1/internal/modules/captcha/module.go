package captcha

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/captcha/middlewares"
	"github.com/bete7512/goauth/internal/modules/captcha/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CaptchaModule struct {
	deps    config.ModuleDependencies
	service *services.CaptchaService
	config  *CaptchaConfig
}

type CaptchaConfig struct {
	// Captcha provider: "google" or "cloudflare"
	Provider string

	// Google reCAPTCHA v3
	RecaptchaSiteKey   string
	RecaptchaSecretKey string
	RecaptchaThreshold float64 // Score threshold (0.0-1.0)

	// Cloudflare Turnstile
	TurnstileSiteKey   string
	TurnstileSecretKey string

	// Apply captcha to these routes
	ApplyToRoutes []string

	// Exclude captcha from these routes
	ExcludeRoutes []string
}

var _ config.Module = (*CaptchaModule)(nil)

func New(cfg *CaptchaConfig) *CaptchaModule {
	if cfg == nil {
		// Default to no captcha if not configured
		cfg = &CaptchaConfig{
			Provider: "",
		}
	}

	// Set default threshold for reCAPTCHA
	if cfg.Provider == "google" && cfg.RecaptchaThreshold == 0 {
		cfg.RecaptchaThreshold = 0.5
	}

	return &CaptchaModule{
		config: cfg,
	}
}

func (m *CaptchaModule) Name() string {
	return "captcha"
}

func (m *CaptchaModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Initialize captcha service
	m.service = services.NewCaptchaService()

	// Set captcha provider based on configuration
	if m.config.Provider == "google" {
		m.service.SetProvider(&services.GoogleRecaptchaProvider{
			SecretKey: m.config.RecaptchaSecretKey,
			Threshold: m.config.RecaptchaThreshold,
		})
		deps.Logger.Info("Captcha module initialized", "provider", "google")
	} else if m.config.Provider == "cloudflare" {
		m.service.SetProvider(&services.CloudflareTurnstileProvider{
			SecretKey: m.config.TurnstileSecretKey,
		})
		deps.Logger.Info("Captcha module initialized", "provider", "cloudflare")
	} else {
		deps.Logger.Info("Captcha module initialized", "provider", "none")
	}

	return nil
}

func (m *CaptchaModule) Routes() []config.RouteInfo {
	return nil // No routes, only middlewares
}

func (m *CaptchaModule) Middlewares() []config.MiddlewareConfig {
	// Only add middleware if provider is configured
	if m.config.Provider == "" || m.config.Provider == "none" {
		return nil
	}

	// Only apply middleware if there are routes to protect
	if len(m.config.ApplyToRoutes) == 0 {
		return nil
	}

	return []config.MiddlewareConfig{
		{
			Name:        "captcha.verify",
			Middleware:  middlewares.NewCaptchaMiddleware(m.service),
			Priority:    70,
			ApplyTo:     m.config.ApplyToRoutes,
			ExcludeFrom: m.config.ExcludeRoutes,
			Global:      false,
		},
	}
}

func (m *CaptchaModule) Models() []interface{} {
	return nil // No models needed
}

func (m *CaptchaModule) RegisterHooks(events config.EventBus) error {
	return nil
}

func (m *CaptchaModule) Dependencies() []string {
	return nil
}

// GetSiteKey returns the site key for the configured provider
func (m *CaptchaModule) GetSiteKey() string {
	if m.config.Provider == "google" {
		return m.config.RecaptchaSiteKey
	} else if m.config.Provider == "cloudflare" {
		return m.config.TurnstileSiteKey
	}
	return ""
}

// GetProvider returns the configured provider name
func (m *CaptchaModule) GetProvider() string {
	return m.config.Provider
}
