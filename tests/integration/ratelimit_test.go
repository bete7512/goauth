//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func login(handler http.Handler, email string, headers ...map[string]string) *httptest.ResponseRecorder {
	return testhelpers.JSONPost(handler, "/auth/login", map[string]interface{}{"email": email, "password": "wrong-password"}, headers...)
}

// TestRateLimit_RegisteredByDefault: an Auth with no RateLimit config gets the
// module and the default identifier rule stops repeated attempts on one account.
func TestRateLimit_RegisteredByDefault(t *testing.T) {
	a, handler := testhelpers.SetupStatelessWithRateLimit(t, nil, nil)
	_, err := a.GetModule(string(types.RateLimitModule))
	require.NoError(t, err, "rate limit module should be registered by default")

	for i := 0; i < 10; i++ {
		w := login(handler, "nobody@example.com")
		require.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
	}
	w := login(handler, "nobody@example.com")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Equal(t, "0", w.Header().Get("RateLimit-Remaining"))
	body := testhelpers.ParseJSON(t, w.Body)
	assert.Equal(t, string(types.ErrRateLimitExceeded), body["data"].(map[string]interface{})["code"])

	// Other accounts from the same address are still served until the IP rule (30/min) trips.
	w = login(handler, "someone-else@example.com")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRateLimit_IPRuleCoversManyAccounts: spraying different identifiers from
// one address is stopped by a per-IP rule. The rule uses a long window so the
// bucket cannot refill during the test: unknown-account logins spend a
// password hash each, which is slow under the race detector.
func TestRateLimit_IPRuleCoversManyAccounts(t *testing.T) {
	cfg := &config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{{
		Name: "credential_ip", ApplyTo: []types.RouteName{types.RouteLogin}, Key: types.RateLimitKeyIP, Limit: 5, Window: time.Hour,
	}}}
	_, handler := testhelpers.SetupStatelessWithRateLimit(t, cfg, nil)
	for i := 0; i < 5; i++ {
		w := login(handler, fmt.Sprintf("user%d@example.com", i))
		require.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
	}
	w := login(handler, "user-final@example.com")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "a sixth identifier from the same address must be limited")
}

// TestRateLimit_DisabledByConfig: Disabled removes the module entirely.
func TestRateLimit_DisabledByConfig(t *testing.T) {
	a, handler := testhelpers.SetupStatelessWithRateLimit(t, &config.RateLimitModuleConfig{Disabled: true}, nil)
	_, err := a.GetModule(string(types.RateLimitModule))
	require.Error(t, err)
	for i := 0; i < 15; i++ {
		w := login(handler, "nobody@example.com")
		require.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
		assert.Empty(t, w.Header().Get("RateLimit-Limit"))
	}
}

// TestRateLimit_CustomRulesReplaceDefaults: only the configured rule applies.
func TestRateLimit_CustomRulesReplaceDefaults(t *testing.T) {
	cfg := &config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{{
		Name: "login_ip", ApplyTo: []types.RouteName{types.RouteLogin}, Key: types.RateLimitKeyIP, Limit: 2, Window: time.Minute,
	}}}
	_, handler := testhelpers.SetupStatelessWithRateLimit(t, cfg, nil)

	first := login(handler, "nobody@example.com")
	require.Equal(t, http.StatusUnauthorized, first.Code)
	assert.Equal(t, "2", first.Header().Get("RateLimit-Limit"))
	assert.Equal(t, "1", first.Header().Get("RateLimit-Remaining"))
	second := login(handler, "nobody@example.com")
	require.Equal(t, http.StatusUnauthorized, second.Code)
	assert.Equal(t, "0", second.Header().Get("RateLimit-Remaining"))
	third := login(handler, "nobody@example.com")
	require.Equal(t, http.StatusTooManyRequests, third.Code)

	// Signup has no rule in this configuration and keeps working.
	for i := 0; i < 3; i++ {
		w := testhelpers.JSONPost(handler, "/auth/signup", map[string]interface{}{"email": fmt.Sprintf("new%d@example.com", i), "password": "Passw0rd!", "name": "New"})
		require.Equal(t, http.StatusCreated, w.Code, "signup %d", i+1)
	}
}

// TestRateLimit_TrustedProxyAndAllowlist: forwarded headers count only behind
// a trusted proxy, and allowlisted clients are never limited.
func TestRateLimit_TrustedProxyAndAllowlist(t *testing.T) {
	rule := config.RateLimitRuleConfig{Name: "login_ip", ApplyTo: []types.RouteName{types.RouteLogin}, Key: types.RateLimitKeyIP, Limit: 1, Window: time.Minute}

	// httptest requests arrive from 192.0.2.1, which we declare a trusted proxy.
	_, trusted := testhelpers.SetupStatelessWithRateLimit(t,
		&config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{rule}, Allowlist: []string{"203.0.113.99"}},
		[]string{"192.0.2.0/24"})
	require.Equal(t, http.StatusUnauthorized, login(trusted, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.1"}).Code)
	require.Equal(t, http.StatusUnauthorized, login(trusted, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.2"}).Code, "another client behind the proxy")
	require.Equal(t, http.StatusTooManyRequests, login(trusted, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.1"}).Code, "same client again")
	for i := 0; i < 4; i++ {
		require.Equal(t, http.StatusUnauthorized, login(trusted, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.99"}).Code, "allowlisted client %d", i+1)
	}

	// Without trusted proxies the header is ignored and every request shares the peer address.
	_, direct := testhelpers.SetupStatelessWithRateLimit(t, &config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{rule}}, nil)
	require.Equal(t, http.StatusUnauthorized, login(direct, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.1"}).Code)
	require.Equal(t, http.StatusTooManyRequests, login(direct, "a@example.com", map[string]string{"X-Forwarded-For": "203.0.113.2"}).Code, "spoofed header must not create a new budget")
}

// TestRateLimit_SendRuleProtectsForgotPassword: the default send rules stop
// email flooding for one identifier after three requests.
func TestRateLimit_SendRuleProtectsForgotPassword(t *testing.T) {
	_, handler := testhelpers.SetupStatelessWithRateLimit(t, nil, nil)
	for i := 0; i < 3; i++ {
		w := testhelpers.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"email": "target@example.com"})
		require.Equal(t, http.StatusOK, w.Code, "send %d", i+1)
	}
	w := testhelpers.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"email": "target@example.com"})
	require.Equal(t, http.StatusTooManyRequests, w.Code)
}
