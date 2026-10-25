package middlewares

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/ratelimit/limiter"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

type recordingBus struct {
	mu     sync.Mutex
	events []*types.RateLimitExceededData
}

func (b *recordingBus) Subscribe(types.EventType, types.EventHandler, ...interface{}) {}
func (b *recordingBus) EmitSync(context.Context, types.EventType, interface{}) error {
	return nil
}
func (b *recordingBus) EmitAsync(_ context.Context, eventType types.EventType, data interface{}) error {
	if eventType != types.EventRateLimitExceeded {
		return errors.New("unexpected event type")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, data.(*types.RateLimitExceededData))
	return nil
}

type failingStore struct{}

func (failingStore) Take(context.Context, string, types.RateLimitRule, time.Time) (types.RateLimitDecision, error) {
	return types.RateLimitDecision{}, errors.New("store down")
}
func (failingStore) Reset(context.Context, string) error { return nil }
func (failingStore) Close() error                        { return nil }

type fixture struct {
	limiter *Limiter
	handler http.Handler
	bodies  []string
	clock   time.Time
}

func newFixture(t *testing.T, opts Options) *fixture {
	t.Helper()
	f := &fixture{clock: time.Unix(1_700_000_000, 0)}
	if opts.Store == nil {
		opts.Store = limiter.NewMemoryStore(0)
	}
	opts.Headers = true
	opts.Now = func() time.Time { return f.clock }
	f.limiter = New(opts)
	f.handler = f.limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	return f
}

func (f *fixture) post(route, remoteAddr, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/x", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), types.RouteNameKey, route))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func ipRule(name string, limit int, routes ...types.RouteName) Rule {
	return Rule{Name: name, ApplyTo: routes, Key: types.RateLimitKeyIP, Budget: types.RateLimitRule{Limit: limit, Window: time.Minute}}
}

func TestPassesThroughWhenNoRuleMatches(t *testing.T) {
	f := newFixture(t, Options{Rules: []Rule{ipRule("login", 1, "core.login")}})
	for i := 0; i < 3; i++ {
		if rec := f.post("core.signup", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, rec.Code)
		}
	}
	if rec := f.post("core.signup", "198.51.100.1:1", `{}`, nil); rec.Header().Get("RateLimit-Limit") != "" {
		t.Fatal("unmatched route carries rate limit headers")
	}
}

func TestRejectsOverLimitWithHeadersAndEnvelope(t *testing.T) {
	bus := &recordingBus{}
	f := newFixture(t, Options{Rules: []Rule{ipRule("login_ip", 2, "core.*")}, Events: bus})
	first := f.post("core.login", "198.51.100.1:1", `{"email":"a@example.com"}`, nil)
	if first.Code != http.StatusOK || first.Header().Get("RateLimit-Remaining") != "1" || first.Header().Get("RateLimit-Limit") != "2" {
		t.Fatalf("first: status %d headers %v", first.Code, first.Header())
	}
	second := f.post("core.login", "198.51.100.1:1", `{"email":"a@example.com"}`, nil)
	if second.Code != http.StatusOK || second.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatalf("second: status %d remaining %q", second.Code, second.Header().Get("RateLimit-Remaining"))
	}
	third := f.post("core.login", "198.51.100.1:1", `{"email":"a@example.com"}`, nil)
	if third.Code != http.StatusTooManyRequests {
		t.Fatalf("third: status %d, want 429", third.Code)
	}
	if third.Header().Get("Retry-After") == "" || third.Header().Get("Retry-After") == "0" {
		t.Fatalf("missing Retry-After: %q", third.Header().Get("Retry-After"))
	}
	if third.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatalf("RateLimit-Remaining = %q on rejection", third.Header().Get("RateLimit-Remaining"))
	}
	var envelope struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(third.Body.Bytes(), &envelope); err != nil || envelope.Data.Code != string(types.ErrRateLimitExceeded) {
		t.Fatalf("body %s (err %v)", third.Body.String(), err)
	}
	if len(f.bodies) != 2 {
		t.Fatalf("handler ran %d times, want 2", len(f.bodies))
	}
	if len(bus.events) != 1 || bus.events[0].Rule != "login_ip" || bus.events[0].Route != "core.login" || bus.events[0].IPAddress != "198.51.100.1" {
		t.Fatalf("events %+v", bus.events)
	}

	// After the window the budget is back.
	f.clock = f.clock.Add(time.Minute)
	if rec := f.post("core.login", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("after window: status %d", rec.Code)
	}
}

func TestIdentifierKeyFollowsTheAccountNotTheAddress(t *testing.T) {
	bus := &recordingBus{}
	rule := Rule{Name: "login_id", ApplyTo: []types.RouteName{"core.login"}, Key: types.RateLimitKeyIdentifier, Budget: types.RateLimitRule{Limit: 1, Window: time.Minute}}
	f := newFixture(t, Options{Rules: []Rule{rule}, Events: bus})
	body := `{"email":" Victim@Example.com ","password":"x"}`
	if rec := f.post("core.login", "198.51.100.1:1", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := f.post("core.login", "198.51.100.2:1", `{"email":"victim@example.com","password":"y"}`, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second from another address: %d, want 429", rec.Code)
	}
	if rec := f.post("core.login", "198.51.100.2:1", `{"username":"someone-else"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("different identifier: %d", rec.Code)
	}
	if rec := f.post("core.login", "198.51.100.2:1", `{"password":"no-identifier"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("no identifier should skip identifier rule: %d", rec.Code)
	}
	if f.bodies[0] != body {
		t.Fatalf("handler saw body %q, want the original", f.bodies[0])
	}
	if len(bus.events) != 1 || bus.events[0].KeyHash == "" || strings.Contains(bus.events[0].KeyHash, "victim") {
		t.Fatalf("event must carry a digest, got %+v", bus.events)
	}
}

func TestTrustedProxiesControlForwardedHeaders(t *testing.T) {
	trusted, _ := http_utils.ParseCIDRs([]string{"10.0.0.0/8"})
	f := newFixture(t, Options{Rules: []Rule{ipRule("login_ip", 1, "core.login")}, TrustedProxies: trusted})
	if rec := f.post("core.login", "10.0.0.1:1", `{}`, map[string]string{"X-Forwarded-For": "203.0.113.1"}); rec.Code != http.StatusOK {
		t.Fatalf("client one: %d", rec.Code)
	}
	if rec := f.post("core.login", "10.0.0.1:1", `{}`, map[string]string{"X-Forwarded-For": "203.0.113.2"}); rec.Code != http.StatusOK {
		t.Fatalf("client two behind the same proxy: %d", rec.Code)
	}
	if rec := f.post("core.login", "10.0.0.1:1", `{}`, map[string]string{"X-Forwarded-For": "203.0.113.1"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("client one again: %d, want 429", rec.Code)
	}

	untrusted := newFixture(t, Options{Rules: []Rule{ipRule("login_ip", 1, "core.login")}})
	untrusted.post("core.login", "198.51.100.1:1", `{}`, map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if rec := untrusted.post("core.login", "198.51.100.1:1", `{}`, map[string]string{"X-Forwarded-For": "203.0.113.2"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed header must not reset the budget: %d", rec.Code)
	}
}

func TestIPv6ClientsShareAPrefixBucket(t *testing.T) {
	f := newFixture(t, Options{Rules: []Rule{ipRule("login_ip", 1, "core.login")}})
	f.post("core.login", "[2001:db8:1:2:aaaa::1]:1", `{}`, nil)
	if rec := f.post("core.login", "[2001:db8:1:2:bbbb::9]:1", `{}`, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rotating within the /64 evaded the limit: %d", rec.Code)
	}
	if rec := f.post("core.login", "[2001:db8:1:3::1]:1", `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("different /64 limited: %d", rec.Code)
	}
}

func TestAllowlistBypassesAllRules(t *testing.T) {
	allow, _ := http_utils.ParseCIDRs([]string{"198.51.100.0/24"})
	f := newFixture(t, Options{Rules: []Rule{ipRule("login_ip", 1, "core.login")}, Allowlist: allow})
	for i := 0; i < 5; i++ {
		if rec := f.post("core.login", "198.51.100.7:1", `{}`, nil); rec.Code != http.StatusOK {
			t.Fatalf("allowlisted request %d: %d", i+1, rec.Code)
		}
	}
}

func TestExcludeFromRemovesRoutes(t *testing.T) {
	rule := ipRule("all_core", 1, "core.*")
	rule.ExcludeFrom = []types.RouteName{"core.me"}
	f := newFixture(t, Options{Rules: []Rule{rule}})
	f.post("core.me", "198.51.100.1:1", `{}`, nil)
	if rec := f.post("core.me", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("excluded route limited: %d", rec.Code)
	}
	f.post("core.login", "198.51.100.1:1", `{}`, nil)
	if rec := f.post("core.login", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("included route not limited: %d", rec.Code)
	}
}

func TestTightestRemainingWinsHeaders(t *testing.T) {
	f := newFixture(t, Options{Rules: []Rule{ipRule("loose", 10, "core.login"), ipRule("tight", 2, "core.login")}})
	rec := f.post("core.login", "198.51.100.1:1", `{}`, nil)
	if rec.Header().Get("RateLimit-Limit") != "2" || rec.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatalf("headers %v", rec.Header())
	}
}

func TestStoreFailureFailsOpenUnlessConfigured(t *testing.T) {
	open := newFixture(t, Options{Store: failingStore{}, Rules: []Rule{ipRule("login_ip", 1, "core.login")}})
	if rec := open.post("core.login", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("fail-open: %d", rec.Code)
	}
	closed := newFixture(t, Options{Store: failingStore{}, Rules: []Rule{ipRule("login_ip", 1, "core.login")}, FailClosed: true})
	if rec := closed.post("core.login", "198.51.100.1:1", `{}`, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed: %d, want 503", rec.Code)
	}
}

func TestOversizedBodySkipsIdentifierButStillReachesHandler(t *testing.T) {
	rule := Rule{Name: "id", ApplyTo: []types.RouteName{"core.login"}, Key: types.RateLimitKeyIdentifier, Budget: types.RateLimitRule{Limit: 1, Window: time.Minute}}
	f := newFixture(t, Options{Rules: []Rule{rule}, MaxBodyBytes: 32})
	big := `{"email":"a@example.com","pad":"` + strings.Repeat("x", 64) + `"}`
	for i := 0; i < 2; i++ {
		if rec := f.post("core.login", "198.51.100.1:1", big, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, rec.Code)
		}
	}
	if f.bodies[0] != big {
		t.Fatal("oversized body was not restored intact")
	}
}
