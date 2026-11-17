//go:build integration

package testhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/stretchr/testify/require"
)

// Fixtures of the identity provider tests.
const (
	IDPClientID     = "test-app"
	IDPClientSecret = "test-app-secret-0123456789abcdef0123456789"
	IDPRedirectURI  = "https://rp.example.test/callback"
	IDPConsentURL   = "https://app.example.test/oidc/consent"
	// IDPBase is where the module's routes live on the test handler.
	IDPBase = "/auth/oidc"
)

// RSAKeyPEM generates an RSA private key in PEM form.
func RSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// IDPServer is an identity provider served over real HTTP, so that an
// OpenID Connect client library can talk to it.
type IDPServer struct {
	Auth    *auth.Auth
	Handler http.Handler
	Server  *httptest.Server
	// Issuer is the issuer identifier clients are configured with.
	Issuer string
	Module config.Module
}

// IDPOptions adjusts SetupIDP.
type IDPOptions struct {
	// Module changes the module configuration before the module is created.
	Module func(*config.IDPModuleConfig)
	// Root changes the root configuration.
	Root func(*config.Config)
	// Use registers further modules before the identity provider.
	Use []config.Module
	// OwnPage leaves ConsentURL empty, so the module serves the sign-in and
	// consent page itself. Otherwise the host's page is IDPConsentURL.
	OwnPage bool
}

// SetupIDP creates a stateless auth instance with the admin, audit and
// identity provider modules, listening on a loopback address.
func SetupIDP(t *testing.T, opts IDPOptions) *IDPServer {
	t.Helper()
	// The listener exists before the handler does: the issuer has to be
	// known when the module is configured.
	server := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + server.Listener.Addr().String()

	root := &config.Config{
		Storage:        newStore(t),
		BasePath:       "/auth",
		APIURL:         baseURL,
		Security:       defaultSecurityConfig("idp-integration-secret-key-32chr", "idp-integration-encryption-key!!"),
		Core:           &config.CoreConfig{RequireEmailVerification: false},
		FrontendConfig: &config.FrontendConfig{URL: "https://app.example.test"},
		RateLimit:      &config.RateLimitModuleConfig{Disabled: true},
		Migration:      config.MigrationConfig{Auto: true},
	}
	if opts.Root != nil {
		opts.Root(root)
	}
	authInstance, err := auth.New(root)
	require.NoError(t, err)
	require.NoError(t, authInstance.Use(admin.New(nil)))
	require.NoError(t, authInstance.Use(audit.New(nil)))
	for _, module := range opts.Use {
		require.NoError(t, authInstance.Use(module))
	}

	cfg := &config.IDPModuleConfig{
		SigningKey: config.IDPSigningKey{PrivateKeyPEM: RSAKeyPEM(t)},
		ConsentURL: IDPConsentURL,
		AdminAPI:   true,
		Clients: []config.IDPClientConfig{{
			ClientID: IDPClientID, Secret: IDPClientSecret, Name: "Test Application",
			RedirectURIs: []string{IDPRedirectURI},
			Scopes:       []string{"openid", "profile", "email", "phone", "offline_access"},
		}},
	}
	if opts.OwnPage {
		cfg.ConsentURL = ""
		cfg.AppName = "Acme"
	}
	if opts.Module != nil {
		opts.Module(cfg)
	}
	module := idp.New(cfg)
	require.NoError(t, authInstance.Use(module))

	handler := initAuth(t, authInstance)
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	return &IDPServer{Auth: authInstance, Handler: handler, Server: server, Issuer: baseURL + IDPBase, Module: module}
}

// PKCEPair returns a code verifier and its S256 challenge.
func PKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// IDPAuthorizeParams returns the parameters of a well-formed authentication
// request for the default client.
func IDPAuthorizeParams(challenge string) url.Values {
	return url.Values{
		"client_id":             {IDPClientID},
		"redirect_uri":          {IDPRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-456"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

// IDPAuthorize sends an authentication request the way a browser would.
func IDPAuthorize(handler http.Handler, params url.Values) *httptest.ResponseRecorder {
	return JSONGet(handler, IDPBase+"/authorize?"+params.Encode())
}

// IDPRequestID starts a sign-in and returns the request the consent page is
// handed.
func IDPRequestID(t *testing.T, handler http.Handler, params url.Values) string {
	t.Helper()
	w := IDPAuthorize(handler, params)
	require.Equal(t, http.StatusFound, w.Code, "authorize: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(location.String(), IDPConsentURL), "expected a redirect to the consent page, got %s", location)
	requestID := location.Query().Get("request_id")
	require.NotEmpty(t, requestID)
	return requestID
}

// IDPPage starts a sign-in in a browser, the way a client application sends
// its user, and returns the address of the module's own page for it.
func IDPPage(t *testing.T, b *Browser, params url.Values) string {
	t.Helper()
	w := b.Get(IDPBase + "/authorize?" + params.Encode())
	require.Equal(t, http.StatusFound, w.Code, "authorize: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, IDPBase+"/consent", location.Path, "expected a redirect to the module's page, got %s", location)
	require.NotEmpty(t, location.Query().Get("request_id"))
	return location.RequestURI()
}

// IDPApprove approves a pending request as the signed-in user and returns
// the redirect that goes back to the client.
func IDPApprove(t *testing.T, handler http.Handler, accessToken, requestID string) *url.URL {
	t.Helper()
	w := JSONPost(handler, IDPBase+"/consent/"+requestID+"/approve", nil, AuthHeader(accessToken))
	require.Equal(t, http.StatusOK, w.Code, "approve: %s", w.Body.String())
	data := ParseJSON(t, w.Body)["data"].(map[string]interface{})
	target, err := url.Parse(data["redirect_to"].(string))
	require.NoError(t, err)
	return target
}

// IDPCode signs the user in to the default client and returns the
// authorization code the client receives.
func IDPCode(t *testing.T, handler http.Handler, accessToken string, params url.Values) string {
	t.Helper()
	target := IDPApprove(t, handler, accessToken, IDPRequestID(t, handler, params))
	require.True(t, strings.HasPrefix(target.String(), params.Get("redirect_uri")), "unexpected redirect %s", target)
	require.Empty(t, target.Query().Get("error"), "authorization failed: %s", target.Query().Get("error_description"))
	code := target.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

// IDPTokenRequest posts a form to the token endpoint, authenticating the
// default client with HTTP Basic unless the form carries client credentials
// or basic is false.
func IDPTokenRequest(handler http.Handler, form url.Values, basic bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, IDPBase+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(IDPClientID, IDPClientSecret)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// IDPExchange redeems an authorization code for the default client and
// returns the token response.
func IDPExchange(t *testing.T, handler http.Handler, code, verifier string) map[string]interface{} {
	t.Helper()
	w := IDPTokenRequest(handler, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {IDPRedirectURI}, "code_verifier": {verifier},
	}, true)
	require.Equal(t, http.StatusOK, w.Code, "token: %s", w.Body.String())
	return ParseJSON(t, w.Body)
}
