package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type noopLogger struct{}

func (noopLogger) Info(string, ...interface{})                      {}
func (noopLogger) Error(string, ...interface{})                     {}
func (noopLogger) Debug(string, ...interface{})                     {}
func (noopLogger) Warn(string, ...interface{})                      {}
func (noopLogger) Trace(string, ...interface{})                     {}
func (noopLogger) Infof(string, ...interface{})                     {}
func (noopLogger) Tracef(string, ...interface{})                    {}
func (noopLogger) Errorf(string, ...interface{})                    {}
func (noopLogger) Debugf(string, ...interface{})                    {}
func (noopLogger) Warnf(string, ...interface{})                     {}
func (noopLogger) Fatalf(string, ...interface{})                    {}
func (l noopLogger) WithFields(map[string]interface{}) types.Logger { return l }

func deps(cfg *config.Config) config.ModuleDependencies {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return config.ModuleDependencies{Logger: noopLogger{}, Config: cfg}
}

func TestDefaultRulesCompile(t *testing.T) {
	rules, err := compileRules(DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(DefaultRules()) {
		t.Fatalf("compiled %d rules, want %d", len(rules), len(DefaultRules()))
	}
}

func TestNilConfigRegistersOneGlobalMiddleware(t *testing.T) {
	m := New(nil)
	if m.Name() != string(types.RateLimitModule) {
		t.Fatalf("name %q", m.Name())
	}
	if err := m.Init(context.Background(), deps(nil)); err != nil {
		t.Fatal(err)
	}
	mws := m.Middlewares()
	if len(mws) != 1 || mws[0].Name != types.MiddlewareRateLimit || !mws[0].Global || mws[0].Priority != middlewarePriority {
		t.Fatalf("middlewares %+v", mws)
	}
	if m.Routes() != nil || m.Dependencies() != nil || len(m.OpenAPISpecs()) == 0 {
		t.Fatal("unexpected routes, dependencies or empty spec")
	}
	if !m.ownsStore {
		t.Fatal("module should own the default memory store")
	}
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledRegistersNothing(t *testing.T) {
	m := New(&config.RateLimitModuleConfig{Disabled: true})
	if err := m.Init(context.Background(), deps(nil)); err != nil {
		t.Fatal(err)
	}
	if m.Middlewares() != nil {
		t.Fatal("disabled module registered middleware")
	}
}

func TestExtraRulesAreAppendedToDefaults(t *testing.T) {
	m := New(&config.RateLimitModuleConfig{ExtraRules: []config.RateLimitRuleConfig{{Name: "me", ApplyTo: []types.RouteName{types.RouteMe}, Limit: 5, Window: time.Minute}}})
	active := m.activeRules()
	if len(active) != len(DefaultRules())+1 || active[len(active)-1].Name != "me" {
		t.Fatalf("active rules %d", len(active))
	}
}

func TestRulesReplaceDefaults(t *testing.T) {
	m := New(&config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{{Name: "only", ApplyTo: []types.RouteName{types.RouteLogin}, Limit: 1, Window: time.Minute}}})
	if active := m.activeRules(); len(active) != 1 {
		t.Fatalf("active rules %d, want 1", len(active))
	}
}

func TestInitRejectsInvalidConfiguration(t *testing.T) {
	valid := config.RateLimitRuleConfig{Name: "a", ApplyTo: []types.RouteName{types.RouteLogin}, Limit: 1, Window: time.Minute}
	cases := map[string]*config.RateLimitModuleConfig{
		"duplicate name": {Rules: []config.RateLimitRuleConfig{valid, valid}},
		"empty name":     {Rules: []config.RateLimitRuleConfig{{ApplyTo: valid.ApplyTo, Limit: 1, Window: time.Minute}}},
		"no routes":      {Rules: []config.RateLimitRuleConfig{{Name: "x", Limit: 1, Window: time.Minute}}},
		"zero limit":     {Rules: []config.RateLimitRuleConfig{{Name: "x", ApplyTo: valid.ApplyTo, Window: time.Minute}}},
		"zero window":    {Rules: []config.RateLimitRuleConfig{{Name: "x", ApplyTo: valid.ApplyTo, Limit: 1}}},
		"negative burst": {Rules: []config.RateLimitRuleConfig{{Name: "x", ApplyTo: valid.ApplyTo, Limit: 1, Window: time.Minute, Burst: -1}}},
		"unknown key":    {Rules: []config.RateLimitRuleConfig{{Name: "x", ApplyTo: valid.ApplyTo, Limit: 1, Window: time.Minute, Key: "user"}}},
		"bad allowlist":  {Allowlist: []string{"nope"}},
	}
	for name, cfg := range cases {
		if err := New(cfg).Init(context.Background(), deps(nil)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := New(nil).Init(context.Background(), deps(&config.Config{TrustedProxies: []string{"bad"}})); err == nil {
		t.Error("bad trusted proxies: expected error")
	}
}

func TestNewSnapshotsConfig(t *testing.T) {
	cfg := &config.RateLimitModuleConfig{Allowlist: []string{"10.0.0.0/8"}, Rules: []config.RateLimitRuleConfig{{Name: "a", ApplyTo: []types.RouteName{types.RouteLogin}, Limit: 1, Window: time.Minute}}}
	m := New(cfg)
	cfg.Allowlist[0] = "changed"
	cfg.Rules[0].ApplyTo[0] = "changed"
	if m.config.Allowlist[0] != "10.0.0.0/8" || m.config.Rules[0].ApplyTo[0] != types.RouteLogin {
		t.Fatal("module config shares memory with caller")
	}
}
