package ratelimiter

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/ratelimiter/middlewares"
	"github.com/bete7512/goauth/internal/modules/ratelimiter/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type RateLimiterModule struct {
	deps     config.ModuleDependencies
	services map[string]*services.RateLimiterService // tier name → service
	config   *RateLimiterConfig
}

// RateLimitTier defines rate limiting configuration for a tier
type RateLimitTier struct {
	Name              string
	RequestsPerMinute int
	RequestsPerHour   int
	BurstSize         int
	IdentifyBy        []string // ["ip", "user_id"] - identification strategies
}

// RateLimiterConfig defines rate limiting configuration
type RateLimiterConfig struct {
	Default *RateLimitTier              // Default tier for all routes
	Tiers   map[string]*RateLimitTier   // Named tiers
	Routes  map[types.RouteName]string  // Route name → tier name
}

var _ config.Module = (*RateLimiterModule)(nil)

func New(cfg ...*RateLimiterConfig) *RateLimiterModule {
	var moduleConfig *RateLimiterConfig
	if len(cfg) > 0 && cfg[0] != nil {
		moduleConfig = cfg[0]
	}

	// Ensure we have a default tier
	if moduleConfig == nil || moduleConfig.Default == nil {
		moduleConfig = &RateLimiterConfig{
			Default: &RateLimitTier{
				Name:              "default",
				RequestsPerMinute: 60,
				RequestsPerHour:   1000,
				BurstSize:         10,
				IdentifyBy:        []string{"ip"},
			},
		}
	}

	// Initialize Tiers map if nil
	if moduleConfig.Tiers == nil {
		moduleConfig.Tiers = make(map[string]*RateLimitTier)
	}

	// Initialize Routes map if nil
	if moduleConfig.Routes == nil {
		moduleConfig.Routes = make(map[types.RouteName]string)
	}

	return &RateLimiterModule{
		config:   moduleConfig,
		services: make(map[string]*services.RateLimiterService),
	}
}

func (m *RateLimiterModule) Name() string {
	return "ratelimiter"
}

func (m *RateLimiterModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Initialize service for default tier
	m.services["default"] = services.NewRateLimiterServiceWithTier(
		"default",
		m.config.Default.RequestsPerMinute,
		m.config.Default.RequestsPerHour,
		m.config.Default.BurstSize,
	)

	// Initialize services for each named tier
	for name, tier := range m.config.Tiers {
		m.services[name] = services.NewRateLimiterServiceWithTier(
			tier.Name,
			tier.RequestsPerMinute,
			tier.RequestsPerHour,
			tier.BurstSize,
		)
	}

	return nil
}

func (m *RateLimiterModule) Routes() []config.RouteInfo {
	return nil // No routes, only middlewares
}

func (m *RateLimiterModule) Middlewares() []config.MiddlewareConfig {
	middlewareConfigs := []config.MiddlewareConfig{}

	// Group routes by tier
	tierRoutes := make(map[string][]types.RouteName)
	for route, tierName := range m.config.Routes {
		tierRoutes[tierName] = append(tierRoutes[tierName], route)
	}

	// Create middleware for each tier with specific routes
	for tierName, routes := range tierRoutes {
		service, exists := m.services[tierName]
		if !exists {
			continue
		}

		tier := m.getTier(tierName)
		if tier == nil {
			continue
		}

		strategy := middlewares.StrategyFromNames(tier.IdentifyBy)

		middlewareConfigs = append(middlewareConfigs, config.MiddlewareConfig{
			Name:       "ratelimiter." + tierName,
			Middleware: middlewares.NewRateLimitMiddlewareWithStrategy(service, strategy),
			Priority:   80,
			ApplyTo:    routes,
		})
	}

	// Default tier middleware (applies globally, runs last among rate limiters)
	defaultStrategy := middlewares.StrategyFromNames(m.config.Default.IdentifyBy)
	middlewareConfigs = append(middlewareConfigs, config.MiddlewareConfig{
		Name:       "ratelimiter.default",
		Middleware: middlewares.NewRateLimitMiddlewareWithStrategy(m.services["default"], defaultStrategy),
		Priority:   79, // Slightly lower than tier-specific
		Global:     true,
	})

	return middlewareConfigs
}

func (m *RateLimiterModule) Models() []interface{} {
	return nil // No models needed (uses in-memory storage)
}

func (m *RateLimiterModule) RegisterHooks(events types.EventBus) error {
	// Rate limiter can listen to events for observability
	// For now, no hooks registered
	return nil
}

func (m *RateLimiterModule) Dependencies() []string {
	return nil
}

func (m *RateLimiterModule) SwaggerSpec() []byte {
	return nil
}

// getTier retrieves a tier by name (checks both Default and Tiers)
func (m *RateLimiterModule) getTier(name string) *RateLimitTier {
	if name == "default" {
		return m.config.Default
	}
	return m.config.Tiers[name]
}
