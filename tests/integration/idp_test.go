//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// idpUser creates a user, signs in and returns the user ID and access token.
func idpUser(t *testing.T, handler http.Handler, email string) (string, string) {
	t.Helper()
	token, _ := h.SignupAndLogin(t, handler, email, "Test1234", "Ada Lovelace")
	return h.Me(t, handler, token)["id"].(string), token
}

// consentDetails reads a pending request as the signed-in user.
func consentDetails(t *testing.T, handler http.Handler, token, requestID string) map[string]interface{} {
	t.Helper()
	w := h.JSONGet(handler, h.IDPBase+"/consent/"+requestID, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "consent details: %s", w.Body.String())
	return h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
}

// errorRedirect asserts that an authorization request was answered with an
// error redirect to the client and returns its parameters.
func errorRedirect(t *testing.T, handler http.Handler, params url.Values) url.Values {
	t.Helper()
	w := h.IDPAuthorize(handler, params)
	require.Equal(t, http.StatusFound, w.Code, "authorize: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(location.String(), h.IDPRedirectURI), "expected a redirect to the client, got %s", location)
	return location.Query()
}

// The discovery document and key set are read by an independent OpenID
// Connect client library, the way a relying party would.
func TestIDP_DiscoveryAndKeys(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})

	provider, err := oidc.NewProvider(context.Background(), idp.Issuer)
	require.NoError(t, err, "a client library must accept the discovery document")
	endpoint := provider.Endpoint()
	assert.Equal(t, idp.Issuer+"/authorize", endpoint.AuthURL)
	assert.Equal(t, idp.Issuer+"/token", endpoint.TokenURL)

	var document struct {
		Issuer        string   `json:"issuer"`
		UserInfo      string   `json:"userinfo_endpoint"`
		JWKSURI       string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		SubjectTypes  []string `json:"subject_types_supported"`
		Algorithms    []string `json:"id_token_signing_alg_values_supported"`
		Scopes        []string `json:"scopes_supported"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	require.NoError(t, provider.Claims(&document))
	assert.Equal(t, idp.Issuer, document.Issuer)
	assert.Equal(t, idp.Issuer+"/userinfo", document.UserInfo)
	assert.Equal(t, idp.Issuer+"/jwks", document.JWKSURI)
	assert.Equal(t, []string{"code"}, document.ResponseTypes)
	assert.Equal(t, []string{"public"}, document.SubjectTypes)
	assert.Equal(t, []string{"RS256"}, document.Algorithms)
	assert.Contains(t, document.Scopes, "openid")
	assert.Equal(t, []string{"S256"}, document.PKCE)

	w := h.JSONGet(idp.Handler, h.IDPBase+"/jwks")
	require.Equal(t, http.StatusOK, w.Code)
	keys := h.ParseJSON(t, w.Body)["keys"].([]interface{})
	require.Len(t, keys, 1)
	key := keys[0].(map[string]interface{})
	assert.Equal(t, "RSA", key["kty"])
	assert.NotEmpty(t, key["kid"])
	assert.NotContains(t, key, "d", "the key set must not contain private key material")
}

// A complete sign-in, with go-oidc and x/oauth2 playing the client
// application: authorize, approve, redeem the code, verify the ID token
// against the published keys, and read UserInfo.
func TestIDP_SignIn_EndToEnd(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	ctx := context.Background()
	userID, token := idpUser(t, idp.Handler, "ada@example.com")

	provider, err := oidc.NewProvider(ctx, idp.Issuer)
	require.NoError(t, err)
	client := oauth2.Config{
		ClientID: h.IDPClientID, ClientSecret: h.IDPClientSecret, RedirectURL: h.IDPRedirectURI,
		Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	verifier := oauth2.GenerateVerifier()
	authURL, err := url.Parse(client.AuthCodeURL("state-123", oidc.Nonce("nonce-456"), oauth2.S256ChallengeOption(verifier)))
	require.NoError(t, err)

	// The browser is sent to the host's consent page with the request.
	requestID := h.IDPRequestID(t, idp.Handler, authURL.Query())
	details := consentDetails(t, idp.Handler, token, requestID)
	assert.Equal(t, "Test Application", details["client"].(map[string]interface{})["name"])
	assert.Equal(t, "rp.example.test", details["redirect_host"])
	assert.Equal(t, true, details["consent_required"], "a first sign-in asks for consent")
	assert.Equal(t, false, details["login_required"])
	assert.Len(t, details["scopes"], 3)

	redirect := h.IDPApprove(t, idp.Handler, token, requestID)
	assert.Equal(t, "state-123", redirect.Query().Get("state"))
	assert.Equal(t, idp.Issuer, redirect.Query().Get("iss"))
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code)

	tokens, err := client.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	require.NoError(t, err, "the client library must be able to redeem the code")
	assert.Equal(t, "Bearer", tokens.TokenType)
	assert.Empty(t, tokens.RefreshToken, "no refresh token without offline_access")
	rawIDToken, ok := tokens.Extra("id_token").(string)
	require.True(t, ok, "the token response carries an ID token")

	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID}).Verify(ctx, rawIDToken)
	require.NoError(t, err, "the ID token must verify against the published keys")
	assert.Equal(t, userID, idToken.Subject)
	assert.Equal(t, "nonce-456", idToken.Nonce)
	require.NoError(t, idToken.VerifyAccessToken(tokens.AccessToken), "at_hash must match the access token")
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified *bool    `json:"email_verified"`
		Name          string   `json:"name"`
		AuthTime      int64    `json:"auth_time"`
		AMR           []string `json:"amr"`
	}
	require.NoError(t, idToken.Claims(&claims))
	assert.Equal(t, "ada@example.com", claims.Email)
	require.NotNil(t, claims.EmailVerified)
	assert.Equal(t, "Ada Lovelace", claims.Name)
	assert.InDelta(t, time.Now().Unix(), claims.AuthTime, 60, "auth_time is when the user signed in")
	assert.NotEmpty(t, claims.AMR)

	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
	require.NoError(t, err)
	assert.Equal(t, userID, info.Subject)
	assert.Equal(t, "ada@example.com", info.Email)
}

// A request whose client or redirect URI cannot be verified is never
// answered with a redirect.
func TestIDP_Authorize_UnverifiedTargetIsNotRedirected(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, challenge := h.PKCEPair(t)

	cases := map[string]func(url.Values){
		"unknown client":          func(p url.Values) { p.Set("client_id", "nobody") },
		"unregistered redirect":   func(p url.Values) { p.Set("redirect_uri", "https://evil.example.test/callback") },
		"redirect with extra":     func(p url.Values) { p.Set("redirect_uri", h.IDPRedirectURI+"/more") },
		"missing redirect":        func(p url.Values) { p.Del("redirect_uri") },
		"missing client":          func(p url.Values) { p.Del("client_id") },
		"client id in other case": func(p url.Values) { p.Set("client_id", strings.ToUpper(h.IDPClientID)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			params := h.IDPAuthorizeParams(challenge)
			change(params)
			w := h.IDPAuthorize(idp.Handler, params)
			require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
			assert.Empty(t, w.Header().Get("Location"))
			assert.Contains(t, []interface{}{"invalid_client", "invalid_request"}, h.ParseJSON(t, w.Body)["error"])
		})
	}
}

// With an ErrorURL configured, such an error is shown on the host's page.
func TestIDP_Authorize_ErrorPage(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.ErrorURL = "https://app.example.test/oidc/error"
	}})
	_, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("redirect_uri", "https://evil.example.test/callback")

	w := h.IDPAuthorize(idp.Handler, params)
	require.Equal(t, http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "app.example.test", location.Host)
	assert.Equal(t, "invalid_request", location.Query().Get("error"))
}

// Once the redirect URI is verified, errors go back to the client with its
// state and this server's issuer.
func TestIDP_Authorize_ErrorsGoBackToTheClient(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, challenge := h.PKCEPair(t)

	cases := map[string]struct {
		change func(url.Values)
		want   string
	}{
		"no openid scope":        {func(p url.Values) { p.Set("scope", "profile email") }, "invalid_scope"},
		"implicit flow":          {func(p url.Values) { p.Set("response_type", "id_token") }, "unsupported_response_type"},
		"hybrid flow":            {func(p url.Values) { p.Set("response_type", "code id_token") }, "unsupported_response_type"},
		"no PKCE":                {func(p url.Values) { p.Del("code_challenge"); p.Del("code_challenge_method") }, "invalid_request"},
		"plain PKCE":             {func(p url.Values) { p.Set("code_challenge_method", "plain") }, "invalid_request"},
		"fragment response mode": {func(p url.Values) { p.Set("response_mode", "fragment") }, "invalid_request"},
		"silent sign-in":         {func(p url.Values) { p.Set("prompt", "none") }, "interaction_required"},
		"request object":         {func(p url.Values) { p.Set("request", "eyJhbGciOiJub25lIn0.e30.") }, "request_not_supported"},
		"request uri":            {func(p url.Values) { p.Set("request_uri", "https://rp.example.test/request") }, "request_uri_not_supported"},
		"repeated scope":         {func(p url.Values) { p.Add("scope", "openid") }, "invalid_request"},
		"negative max_age":       {func(p url.Values) { p.Set("max_age", "-1") }, "invalid_request"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			params := h.IDPAuthorizeParams(challenge)
			tc.change(params)
			query := errorRedirect(t, idp.Handler, params)
			assert.Equal(t, tc.want, query.Get("error"))
			assert.Equal(t, "state-123", query.Get("state"))
			assert.Equal(t, idp.Issuer, query.Get("iss"))
			assert.Empty(t, query.Get("code"))
		})
	}
}

// Scopes the client is not registered for are left out, not refused.
func TestIDP_Authorize_DropsScopesTheClientMayNotHave(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.Clients[0].Scopes = []string{"openid", "email"}
	}})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	verifier, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("scope", "openid email profile offline_access groups")

	response := h.IDPExchange(t, idp.Handler, h.IDPCode(t, idp.Handler, token, params), verifier)
	assert.Equal(t, "openid email", response["scope"])
	assert.NotContains(t, response, "refresh_token")
}

func TestIDP_Consent_NeedsASignedInUser(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, challenge := h.PKCEPair(t)
	requestID := h.IDPRequestID(t, idp.Handler, h.IDPAuthorizeParams(challenge))

	for _, path := range []string{"", "/approve", "/deny"} {
		var code int
		if path == "" {
			code = h.JSONGet(idp.Handler, h.IDPBase+"/consent/"+requestID).Code
		} else {
			code = h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+path, nil).Code
		}
		assert.Equal(t, http.StatusUnauthorized, code, "path %q", path)
	}
}

// Consent is remembered per user and application, asked again when the
// application wants more or insists, and never asked for an application the
// host operates itself.
func TestIDP_Consent_RememberedAndSkipped(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.Clients = append(cfg.Clients, config.IDPClientConfig{
			ClientID: "first-party", Secret: h.IDPClientSecret, Name: "Our Own App",
			RedirectURIs: []string{h.IDPRedirectURI}, SkipConsent: true,
		})
	}})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	_, other := idpUser(t, idp.Handler, "grace@example.com")
	_, challenge := h.PKCEPair(t)
	required := func(token string, change func(url.Values)) interface{} {
		params := h.IDPAuthorizeParams(challenge)
		if change != nil {
			change(params)
		}
		return consentDetails(t, idp.Handler, token, h.IDPRequestID(t, idp.Handler, params))["consent_required"]
	}

	assert.Equal(t, true, required(token, nil), "first sign-in")
	h.IDPCode(t, idp.Handler, token, h.IDPAuthorizeParams(challenge))
	assert.Equal(t, false, required(token, nil), "the same scopes again")
	assert.Equal(t, false, required(token, func(p url.Values) { p.Set("scope", "openid") }), "fewer scopes")
	assert.Equal(t, true, required(token, func(p url.Values) { p.Set("scope", "openid profile email phone") }), "more scopes")
	assert.Equal(t, true, required(token, func(p url.Values) { p.Set("prompt", "consent") }), "the application insists")
	assert.Equal(t, true, required(other, nil), "another user has approved nothing")
	assert.Equal(t, false, required(other, func(p url.Values) { p.Set("client_id", "first-party") }), "the host's own application")
}

// A refusal goes back to the client as access_denied, and the request is
// spent either way.
func TestIDP_Consent_Deny(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	_, challenge := h.PKCEPair(t)
	requestID := h.IDPRequestID(t, idp.Handler, h.IDPAuthorizeParams(challenge))

	w := h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+"/deny", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "deny: %s", w.Body.String())
	target, err := url.Parse(h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["redirect_to"].(string))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(target.String(), h.IDPRedirectURI))
	assert.Equal(t, "access_denied", target.Query().Get("error"))
	assert.Equal(t, "state-123", target.Query().Get("state"))
	assert.Empty(t, target.Query().Get("code"))

	w = h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+"/approve", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, string(types.ErrIDPRequestNotFound), h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["code"])

	// And an approved request cannot be approved twice.
	requestID = h.IDPRequestID(t, idp.Handler, h.IDPAuthorizeParams(challenge))
	h.IDPApprove(t, idp.Handler, token, requestID)
	w = h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+"/approve", nil, h.AuthHeader(token))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// prompt=login and max_age ask for a sign-in newer than the user has. The
// request stays open while the user signs in again.
func TestIDP_PromptLoginAndMaxAge(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	h.Signup(t, idp.Handler, "ada@example.com", "Test1234", "Ada Lovelace")
	stale, _ := h.Login(t, idp.Handler, "ada@example.com", "Test1234")
	// Sign-in times are kept in whole seconds.
	time.Sleep(1100 * time.Millisecond)
	verifier, challenge := h.PKCEPair(t)

	for name, change := range map[string]func(url.Values){
		"prompt=login": func(p url.Values) { p.Set("prompt", "login") },
		"max_age=0":    func(p url.Values) { p.Set("max_age", "0") },
	} {
		t.Run(name, func(t *testing.T) {
			params := h.IDPAuthorizeParams(challenge)
			change(params)
			requestID := h.IDPRequestID(t, idp.Handler, params)
			assert.Equal(t, true, consentDetails(t, idp.Handler, stale, requestID)["login_required"])

			w := h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+"/approve", nil, h.AuthHeader(stale))
			require.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, string(types.ErrIDPLoginRequired), h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["code"])

			requestedAt := time.Now().Unix()
			fresh, _ := h.Login(t, idp.Handler, "ada@example.com", "Test1234")
			assert.Equal(t, false, consentDetails(t, idp.Handler, fresh, requestID)["login_required"])
			redirect := h.IDPApprove(t, idp.Handler, fresh, requestID)
			response := h.IDPExchange(t, idp.Handler, redirect.Query().Get("code"), verifier)

			provider, err := oidc.NewProvider(context.Background(), idp.Issuer)
			require.NoError(t, err)
			idToken, err := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID}).Verify(context.Background(), response["id_token"].(string))
			require.NoError(t, err)
			var claims struct {
				AuthTime int64 `json:"auth_time"`
			}
			require.NoError(t, idToken.Claims(&claims))
			assert.GreaterOrEqual(t, claims.AuthTime, requestedAt-1, "auth_time reports the new sign-in")
		})
	}

	// A sign-in recent enough for max_age needs nothing more.
	params := h.IDPAuthorizeParams(challenge)
	params.Set("max_age", "3600")
	assert.Equal(t, false, consentDetails(t, idp.Handler, stale, h.IDPRequestID(t, idp.Handler, params))["login_required"])
}

// The flow is the same when the host keeps server-side sessions, and
// signing out of the session leaves the application connected.
func TestIDP_WithSessionModule(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Use: []config.Module{session.New(&config.SessionModuleConfig{EnableSessionManagement: true})}})
	ctx := context.Background()
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid email offline_access")

	provider, err := oidc.NewProvider(ctx, idp.Issuer)
	require.NoError(t, err)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID}).Verify(ctx, response["id_token"].(string))
	require.NoError(t, err)
	assert.Equal(t, userID, idToken.Subject)
	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}
	require.NoError(t, idToken.Claims(&claims))
	assert.InDelta(t, time.Now().Unix(), claims.AuthTime, 60, "auth_time is when the session began")

	require.Equal(t, http.StatusOK, h.JSONPost(idp.Handler, "/auth/logout", nil, h.AuthHeader(token)).Code)
	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(idp.Handler, "/auth/me", h.AuthHeader(token)).Code, "the session is over")
	assert.Equal(t, http.StatusOK, userInfo(idp.Handler, response["access_token"].(string)).Code, "the application stays connected")
	assert.Equal(t, http.StatusOK, refreshRequest(idp.Handler, response["refresh_token"].(string)).Code)
}
