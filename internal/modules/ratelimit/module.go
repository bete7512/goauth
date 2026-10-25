// Package ratelimit limits request rates on the built-in HTTP routes. Auth
// registers it during Initialize with the default rules unless
// Config.RateLimit.Disabled is set or the host registers it explicitly.
package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"strings"

	"github.com/bete7512/goauth/internal/modules/ratelimit/limiter"
	"github.com/bete7512/goauth/internal/modules/ratelimit/middlewares"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

// Middleware priority: after request IDs (90), before captcha (70) and auth (50).
const middlewarePriority = 80

// Module enforces per-route request budgets.
type Module struct {
	config    *config.RateLimitModuleConfig
	deps      config.ModuleDependencies
	limiter   *middlewares.Limiter
	store     types.RateLimitStore
	ownsStore bool
}

var (
	_ config.Module         = (*Module)(nil)
	_ config.ModuleShutdown = (*Module)(nil)
)

// New creates the module. A nil config applies DefaultRules with a memory store.
func New(cfg *config.RateLimitModuleConfig) *Module {
	if cfg == nil {
		cfg = &config.RateLimitModuleConfig{}
	} else {
		cfg = cloneConfig(cfg)
	}
	return &Module{config: cfg}
}

func cloneConfig(cfg *config.RateLimitModuleConfig) *config.RateLimitModuleConfig {
	snapshot := *cfg
	snapshot.Rules = cloneRules(cfg.Rules)
	snapshot.ExtraRules = cloneRules(cfg.ExtraRules)
	snapshot.Allowlist = append([]string(nil), cfg.Allowlist...)
	return &snapshot
}

func cloneRules(rules []config.RateLimitRuleConfig) []config.RateLimitRuleConfig {
	if rules == nil {
		return nil
	}
	out := make([]config.RateLimitRuleConfig, len(rules))
	for i, rule := range rules {
		out[i] = rule
		out[i].ApplyTo = append([]types.RouteName(nil), rule.ApplyTo...)
		out[i].ExcludeFrom = append([]types.RouteName(nil), rule.ExcludeFrom...)
	}
	return out
}

// Name implements config.Module.
func (m *Module) Name() string {
	return string(types.RateLimitModule)
}

// Init validates the rules, resolves the store and builds the middleware.
func (m *Module) Init(_ context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	if m.config.Disabled {
		deps.Logger.Info("Rate limiting disabled by configuration")
		return nil
	}
	rules, err := compileRules(m.activeRules())
	if err != nil {
		return fmt.Errorf("ratelimit: %w", err)
	}
	var trusted []net.IPNet
	var maxBody int64
	if deps.Config != nil {
		if trusted, err = http_utils.ParseCIDRs(deps.Config.TrustedProxies); err != nil {
			return fmt.Errorf("ratelimit: trusted proxies: %w", err)
		}
		maxBody = deps.Config.MaxRequestBodyBytes
	}
	allowlist, err := http_utils.ParseCIDRs(m.config.Allowlist)
	if err != nil {
		return fmt.Errorf("ratelimit: allowlist: %w", err)
	}
	store, storeName := m.config.Store, "custom"
	if store == nil {
		store = limiter.NewMemoryStore(m.config.MaxTrackedKeys)
		storeName = "memory"
		m.ownsStore = true
	}
	m.store = store
	m.limiter = middlewares.New(middlewares.Options{
		Store:          store,
		Rules:          rules,
		TrustedProxies: trusted,
		Allowlist:      allowlist,
		FailClosed:     m.config.FailClosed,
		IPv6PrefixBits: m.config.IPv6PrefixBits,
		Headers:        !m.config.DisableHeaders,
		MaxBodyBytes:   maxBody,
		Events:         deps.Events,
		Logger:         deps.Logger,
	})
	deps.Logger.Info("Rate limit module initialized", "rules", len(rules), "store", storeName, "fail_closed", m.config.FailClosed)
	return nil
}

// activeRules returns the configured rules, or the defaults, plus any extras.
func (m *Module) activeRules() []config.RateLimitRuleConfig {
	rules := m.config.Rules
	if rules == nil {
		rules = DefaultRules()
	}
	active := append([]config.RateLimitRuleConfig(nil), rules...)
	return append(active, m.config.ExtraRules...)
}

func compileRules(configs []config.RateLimitRuleConfig) ([]middlewares.Rule, error) {
	seen := make(map[string]bool, len(configs))
	rules := make([]middlewares.Rule, 0, len(configs))
	for i, rc := range configs {
		name := strings.TrimSpace(rc.Name)
		if name == "" {
			return nil, fmt.Errorf("rule %d has no name", i)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate rule name %q", name)
		}
		seen[name] = true
		if len(rc.ApplyTo) == 0 {
			return nil, fmt.Errorf("rule %q applies to no routes", name)
		}
		if rc.Limit <= 0 {
			return nil, fmt.Errorf("rule %q: limit must be positive", name)
		}
		if rc.Window <= 0 {
			return nil, fmt.Errorf("rule %q: window must be positive", name)
		}
		if rc.Burst < 0 {
			return nil, fmt.Errorf("rule %q: burst must not be negative", name)
		}
		key := rc.Key
		if key == "" {
			key = types.RateLimitKeyIP
		}
		switch key {
		case types.RateLimitKeyIP, types.RateLimitKeyIdentifier, types.RateLimitKeyIPIdentifier:
		default:
			return nil, fmt.Errorf("rule %q: unsupported key %q", name, rc.Key)
		}
		rules = append(rules, middlewares.Rule{
			Name:        name,
			ApplyTo:     append([]types.RouteName(nil), rc.ApplyTo...),
			ExcludeFrom: append([]types.RouteName(nil), rc.ExcludeFrom...),
			Key:         key,
			Budget:      types.RateLimitRule{Limit: rc.Limit, Window: rc.Window, Burst: rc.Burst},
		})
	}
	return rules, nil
}

// Routes implements config.Module; the module exposes no endpoints.
func (m *Module) Routes() []config.RouteInfo {
	return nil
}

// Middlewares registers one global middleware that matches rules by route name.
func (m *Module) Middlewares() []config.MiddlewareConfig {
	if m.limiter == nil {
		return nil
	}
	return []config.MiddlewareConfig{{
		Name:       types.MiddlewareRateLimit,
		Middleware: m.limiter.Middleware,
		Priority:   middlewarePriority,
		Global:     true,
	}}
}

// RegisterHooks implements config.Module.
func (m *Module) RegisterHooks(_ types.EventBus) error {
	return nil
}

// Dependencies implements config.Module.
func (m *Module) Dependencies() []string {
	return nil
}

// OpenAPISpecs implements config.Module.
func (m *Module) OpenAPISpecs() []byte {
	return openapiSpec
}

// Migrations implements config.Module; the module has no tables.
func (m *Module) Migrations() types.ModuleMigrations {
	return types.ModuleMigrations{}
}

// Shutdown closes the store when the module created it.
func (m *Module) Shutdown(_ context.Context) error {
	if m.ownsStore && m.store != nil {
		return m.store.Close()
	}
	return nil
}
