package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

func rsaKeyPEM(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func ecKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

const testClientSecret = "0123456789abcdef0123456789abcdef"

func settingsDeps() config.ModuleDependencies {
	return config.ModuleDependencies{Config: &config.Config{
		APIURL:   "https://api.example.com",
		BasePath: "/auth",
		Security: types.SecurityConfig{JwtSecretKey: "test-secret-key-for-unit-tests!!"},
		Core:     &config.CoreConfig{},
		FrontendConfig: &config.FrontendConfig{
			URL: "https://app.example.com/",
		},
	}}
}

func TestResolveSettingsDefaults(t *testing.T) {
	settings, err := ResolveSettings(settingsDeps(), &config.IDPModuleConfig{SigningKey: config.IDPSigningKey{PrivateKeyPEM: rsaKeyPEM(t, 2048)}})
	require.NoError(t, err)

	require.Equal(t, "https://api.example.com/auth/oidc", settings.Issuer)
	require.Equal(t, Endpoints{
		Authorization: "https://api.example.com/auth/oidc/authorize",
		Token:         "https://api.example.com/auth/oidc/token",
		UserInfo:      "https://api.example.com/auth/oidc/userinfo",
		JWKS:          "https://api.example.com/auth/oidc/jwks",
	}, settings.Endpoints)
	require.True(t, settings.BuiltInPage, "the module serves the page when the host names none")
	require.Equal(t, "https://api.example.com/auth/oidc/consent", settings.ConsentURL)
	require.Equal(t, "/auth/oidc", settings.PageBase)
	require.Equal(t, "api.example.com", settings.AppName)
	require.Empty(t, settings.ErrorURL)
	require.Equal(t, time.Hour, settings.IDTokenTTL)
	require.Equal(t, time.Hour, settings.AccessTokenTTL)
	require.Equal(t, 30*24*time.Hour, settings.RefreshTokenTTL)
	require.Equal(t, 10*time.Second, settings.RefreshReuseLeeway)
	require.Equal(t, time.Minute, settings.CodeTTL)
	require.Equal(t, 10*time.Minute, settings.RequestTTL)
	require.False(t, settings.AdminAPI, "the admin API is opt-in")
	require.Equal(t, types.JWTAlgorithmRS256, settings.Signer.Algorithm())
	require.NotEmpty(t, settings.Signer.KeyID())
}

func TestResolveSettingsOverrides(t *testing.T) {
	settings, err := ResolveSettings(settingsDeps(), &config.IDPModuleConfig{
		SigningKey:              config.IDPSigningKey{PrivateKeyPEM: rsaKeyPEM(t, 2048), KeyID: "2026-11"},
		Issuer:                  "https://id.example.com/",
		ConsentURL:              "https://login.example.com/approve",
		ErrorURL:                "https://login.example.com/error",
		IDTokenTTL:              5 * time.Minute,
		RefreshTokenReuseLeeway: -1,
		AdminAPI:                true,
	})
	require.NoError(t, err)
	require.Equal(t, "https://id.example.com", settings.Issuer, "a trailing slash is dropped")
	require.Equal(t, "https://id.example.com/token", settings.Endpoints.Token, "endpoints follow the published issuer")
	require.Equal(t, "https://login.example.com/approve", settings.ConsentURL)
	require.False(t, settings.BuiltInPage, "a host that names its page serves it")
	require.Equal(t, "https://login.example.com/error", settings.ErrorURL)
	require.Equal(t, 5*time.Minute, settings.IDTokenTTL)
	require.Zero(t, settings.RefreshReuseLeeway, "a negative leeway disables it")
	require.True(t, settings.AdminAPI)
	require.Equal(t, "2026-11", settings.Signer.KeyID())
}

func TestResolveSettingsValidation(t *testing.T) {
	key := rsaKeyPEM(t, 2048)
	valid := func() *config.IDPModuleConfig {
		return &config.IDPModuleConfig{SigningKey: config.IDPSigningKey{PrivateKeyPEM: key}}
	}
	client := func(change func(*config.IDPClientConfig)) func(*config.IDPModuleConfig, *config.Config) {
		return func(cfg *config.IDPModuleConfig, _ *config.Config) {
			c := config.IDPClientConfig{ClientID: "app", Secret: testClientSecret, Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}}
			change(&c)
			cfg.Clients = []config.IDPClientConfig{c}
		}
	}

	cases := map[string]struct {
		change func(*config.IDPModuleConfig, *config.Config)
		want   string
	}{
		"no APIURL":         {func(_ *config.IDPModuleConfig, root *config.Config) { root.APIURL = "" }, "Config.APIURL is required"},
		"plain http APIURL": {func(_ *config.IDPModuleConfig, root *config.Config) { root.APIURL = "http://api.example.com" }, "must use https"},
		"no signing key":    {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.SigningKey = config.IDPSigningKey{} }, "SigningKey is required"},
		"EC signing key":    {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.SigningKey.PrivateKeyPEM = ecKeyPEM(t) }, "must be an RSA private key"},
		"short RSA key":     {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.SigningKey.PrivateKeyPEM = rsaKeyPEM(t, 1024) }, "at least 2048 bits"},
		"not a key":         {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.SigningKey.PrivateKeyPEM = []byte("nope") }, "must be an RSA private key"},
		"retired key algorithm": {func(cfg *config.IDPModuleConfig, _ *config.Config) {
			cfg.SigningKey.RetiredKeys = []types.JWTVerificationKey{{ID: "old", Algorithm: types.JWTAlgorithmES256}}
		}, "RetiredKeys must be RS256"},
		"no page for bearer tokens": {func(_ *config.IDPModuleConfig, root *config.Config) {
			root.Security.AuthMode, root.FrontendConfig = types.AuthModeBearer, nil
		}, "ConsentURL is required"},
		"cookies cannot reach the page": {func(_ *config.IDPModuleConfig, root *config.Config) { root.Security.Session.Path = "/app" }, "would never receive the credential cookies"},
		"relative consent page":         {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.ConsentURL = "/consent" }, "ConsentURL"},
		"error page fragment":           {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.ErrorURL = "https://app.example.com/error#x" }, "ErrorURL"},
		"plain http issuer":             {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.Issuer = "http://id.example.com" }, "Issuer"},
		"issuer with a query":           {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.Issuer = "https://id.example.com?tenant=1" }, "must not contain a query"},
		"issuer with fragment":          {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.Issuer = "https://id.example.com#x" }, "must not contain a fragment"},
		"long-lived codes":              {func(cfg *config.IDPModuleConfig, _ *config.Config) { cfg.AuthorizationCodeTTL = time.Hour }, "AuthorizationCodeTTL"},
		"short client secret":           {client(func(c *config.IDPClientConfig) { c.Secret = "short" }), "at least 32 characters"},
		"no client secret":              {client(func(c *config.IDPClientConfig) { c.Secret = "" }), "at least 32 characters"},
		"public with a secret":          {client(func(c *config.IDPClientConfig) { c.Public = true }), "has no Secret"},
		"bad client id":                 {client(func(c *config.IDPClientConfig) { c.ClientID = "my app" }), "ClientID"},
		"duplicate client id": {func(cfg *config.IDPModuleConfig, _ *config.Config) {
			c := config.IDPClientConfig{ClientID: "app", Secret: testClientSecret}
			cfg.Clients = []config.IDPClientConfig{c, c}
		}, "duplicate ClientID"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			deps, cfg := settingsDeps(), valid()
			tc.change(cfg, deps.Config)
			_, err := ResolveSettings(deps, cfg)
			require.ErrorContains(t, err, tc.want)
			require.ErrorContains(t, err, "idp:", "errors name the module")
		})
	}
}

// Which page the browser is sent to: the host's when it names one, the
// module's own when cookies can carry the sign-in, and the frontend's
// conventional address when the application only takes bearer tokens.
func TestResolveSettingsConsentPage(t *testing.T) {
	key := config.IDPSigningKey{PrivateKeyPEM: rsaKeyPEM(t, 2048)}

	published := settingsDeps()
	settings, err := ResolveSettings(published, &config.IDPModuleConfig{SigningKey: key, Issuer: "https://id.example.com/sso", AppName: " Acme "})
	require.NoError(t, err)
	require.True(t, settings.BuiltInPage)
	require.Equal(t, "https://id.example.com/sso/consent", settings.ConsentURL, "the page follows the published issuer")
	require.Equal(t, "/sso", settings.PageBase)
	require.Equal(t, "Acme", settings.AppName)

	root := settingsDeps()
	root.Config.Security.Session.Path = "/auth"
	settings, err = ResolveSettings(root, &config.IDPModuleConfig{SigningKey: key})
	require.NoError(t, err, "a cookie path that covers the page is fine")
	require.True(t, settings.BuiltInPage)

	bearer := settingsDeps()
	bearer.Config.Security.AuthMode = types.AuthModeBearer
	settings, err = ResolveSettings(bearer, &config.IDPModuleConfig{SigningKey: key})
	require.NoError(t, err)
	require.False(t, settings.BuiltInPage, "the module's page needs cookies")
	require.Equal(t, "https://app.example.com/oidc/consent", settings.ConsentURL)

	own := settingsDeps()
	own.Config.Security.Session.Path = "/app"
	settings, err = ResolveSettings(own, &config.IDPModuleConfig{SigningKey: key, ConsentURL: "https://app.example.com/approve"})
	require.NoError(t, err, "the cookie path does not matter to a page of the host's")
	require.False(t, settings.BuiltInPage)
}

func TestResolveSettingsLocalDevelopment(t *testing.T) {
	key := config.IDPSigningKey{PrivateKeyPEM: rsaKeyPEM(t, 2048)}

	loopback := settingsDeps()
	loopback.Config.APIURL = "http://localhost:8080"
	settings, err := ResolveSettings(loopback, &config.IDPModuleConfig{SigningKey: key})
	require.NoError(t, err, "http is accepted on a loopback host")
	require.Equal(t, "http://localhost:8080/auth/oidc", settings.Issuer)

	optIn := settingsDeps()
	optIn.Config.APIURL = "http://api.internal"
	optIn.Config.Security.Session.AllowInsecureCookies = true
	_, err = ResolveSettings(optIn, &config.IDPModuleConfig{SigningKey: key})
	require.NoError(t, err, "http is accepted when the host opted into insecure local development")
}

// The ID token key must not be a key that verifies GoAuth's own access
// tokens, whether it is the active one or a retained one.
func TestResolveSettingsRefusesTheCoreSigningKey(t *testing.T) {
	shared := rsaKeyPEM(t, 2048)
	block, _ := pem.Decode(shared)
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	require.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	cfg := &config.IDPModuleConfig{SigningKey: config.IDPSigningKey{PrivateKeyPEM: shared}}
	const want = "must not be the key that signs GoAuth's access tokens"

	t.Run("from configuration", func(t *testing.T) {
		deps := settingsDeps()
		deps.Config.Security.JWTAlgorithm = types.JWTAlgorithmRS256
		deps.Config.Security.JWTPrivateKeyPEM = shared
		_, err := ResolveSettings(deps, cfg)
		require.ErrorContains(t, err, want)
	})
	t.Run("from the security manager", func(t *testing.T) {
		deps := settingsDeps()
		security := types.SecurityConfig{
			JwtSecretKey: "test-secret-key-for-unit-tests!!", JWTAlgorithm: types.JWTAlgorithmRS256, JWTPrivateKeyPEM: shared,
			Session: types.SessionConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
		}
		deps.SecurityManager = newManager(t, security)
		_, err := ResolveSettings(deps, cfg)
		require.ErrorContains(t, err, want)
	})
	t.Run("a retained key", func(t *testing.T) {
		deps := settingsDeps()
		security := types.SecurityConfig{
			JwtSecretKey: "test-secret-key-for-unit-tests!!", JWTAlgorithm: types.JWTAlgorithmRS256, JWTPrivateKeyPEM: rsaKeyPEM(t, 2048), JWTKeyID: "new",
			RetainedJWTKeys: []types.JWTVerificationKey{{ID: "old", Algorithm: types.JWTAlgorithmRS256, PublicKeyPEM: publicPEM, NotAfter: time.Now().Add(time.Hour)}},
			Session:         types.SessionConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
		}
		deps.SecurityManager = newManager(t, security)
		_, err := ResolveSettings(deps, cfg)
		require.ErrorContains(t, err, want)
	})
	t.Run("a different asymmetric key is fine", func(t *testing.T) {
		deps := settingsDeps()
		deps.Config.Security.JWTAlgorithm = types.JWTAlgorithmRS256
		deps.Config.Security.JWTPrivateKeyPEM = rsaKeyPEM(t, 2048)
		deps.SecurityManager = newManager(t, deps.Config.Security)
		_, err := ResolveSettings(deps, cfg)
		require.NoError(t, err)
	})
}

func newManager(t *testing.T, cfg types.SecurityConfig) types.SecurityManager {
	t.Helper()
	manager := security.NewSecurityManager(cfg)
	require.NoError(t, manager.JWTKeyringError())
	return manager
}
