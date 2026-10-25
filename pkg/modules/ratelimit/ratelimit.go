// Package ratelimit exposes the request rate-limiting module.
// Import this package instead of internal/modules/ratelimit.
//
// Auth registers this module during Initialize with config.Config.RateLimit
// (nil means the default rules and a process-local memory store). Register it
// yourself to use a shared store or custom rules, or set
// config.RateLimitModuleConfig.Disabled to turn rate limiting off.
package ratelimit

import (
	internal "github.com/bete7512/goauth/internal/modules/ratelimit"
	"github.com/bete7512/goauth/internal/modules/ratelimit/limiter"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// New creates the rate-limiting module. A nil config applies DefaultRules
// with a memory store.
func New(cfg *config.RateLimitModuleConfig) config.Module {
	return internal.New(cfg)
}

// DefaultRules returns the built-in rule set. Start from it to adjust limits.
func DefaultRules() []config.RateLimitRuleConfig {
	return internal.DefaultRules()
}

// NewMemoryStore returns the process-local store used when none is configured.
// maxKeys caps tracked keys; zero selects the default.
func NewMemoryStore(maxKeys int) types.RateLimitStore {
	return limiter.NewMemoryStore(maxKeys)
}
