package ratelimiter

import (
	"context"

	"github.com/bete7512/goauth/modules/ratelimiter/middlewares"
	"github.com/bete7512/goauth/modules/ratelimiter/services"
	"github.com/bete7512/goauth/pkg/config"
)

type RateLimiterModule struct {
	deps    config.ModuleDependencies
	service *services.RateLimiterService
	config  *RateLimiterConfig
}

type RateLimiterConfig struct {
	// Rate limiting
	RequestsPerMinute int
	RequestsPerHour   int
	BurstSize         int
}

var _ config.Module = (*RateLimiterModule)(nil)

func New(cfg ...*RateLimiterConfig) *RateLimiterModule {
	var moduleConfig *RateLimiterConfig
	if len(cfg) > 0 && cfg[0] != nil {
		moduleConfig = cfg[0]
	} else {
		moduleConfig = &RateLimiterConfig{
			RequestsPerMinute: 60,
			RequestsPerHour:   1000,
			BurstSize:         10,
		}
	}

	return &RateLimiterModule{
		config: moduleConfig,
	}
}

func (m *RateLimiterModule) Name() string {
	return "ratelimiter"
}

func (m *RateLimiterModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Initialize rate limiter service
	m.service = services.NewRateLimiterService(
		m.config.RequestsPerMinute,
		m.config.RequestsPerHour,
		m.config.BurstSize,
	)

	return nil
}

func (m *RateLimiterModule) Routes() []config.RouteInfo {
	return nil // No routes, only middlewares
}

func (m *RateLimiterModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       "ratelimiter.limit",
			Middleware: middlewares.NewRateLimitMiddleware(m.service),
			Priority:   80,
			Global:     true, // Apply to all routes
		},
	}
}

func (m *RateLimiterModule) Models() []interface{} {
	return nil // No models needed (uses in-memory storage)
}

func (m *RateLimiterModule) RegisterHooks(events config.EventBus) error {
	return nil
}

func (m *RateLimiterModule) Dependencies() []string {
	return nil
}
