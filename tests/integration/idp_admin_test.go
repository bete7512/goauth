//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const idpClients = "/auth/admin/oidc/clients"

// idpAdmin creates a user, makes them an administrator and signs them in.
func idpAdmin(t *testing.T, a *auth.Auth, handler http.Handler) string {
	t.Helper()
	h.Signup(t, handler, "admin@example.com", "Test1234", "Admin")
	users := a.Config().Storage.Core().Users()
	user, err := users.FindByEmail(context.Background(), "admin@example.com")
	require.NoError(t, err)
	user.IsSuperAdmin = true
	require.NoError(t, users.Update(context.Background(), user))
	token, _ := h.Login(t, handler, "admin@example.com", "Test1234")
	return token
}

func envelopeData(t *testing.T, w *httptest.ResponseRecorder, status int) map[string]interface{} {
	t.Helper()
	require.Equal(t, status, w.Code, "body: %s", w.Body.String())
	data, _ := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	return data
}

func newClientBody() map[string]interface{} {
	return map[string]interface{}{
		"name":          "Dashboard",
		"redirect_uris": []string{"https://dashboard.example.test/callback"},
		"scopes":        []string{"openid", "email"},
	}
}

// signInTo runs the whole flow against a given client and returns the token
// endpoint response recorder. secret is empty for a public client.
func signInTo(t *testing.T, handler http.Handler, userToken, clientID, secret, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	verifier, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "openid email")
	code := h.IDPCode(t, handler, userToken, params)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}, "client_id": {clientID}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return h.IDPTokenRequest(handler, form, false)
}

func TestIDP_Admin_RequiresAnAdministrator(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")

	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(idp.Handler, idpClients).Code)
	assert.Equal(t, http.StatusForbidden, h.JSONGet(idp.Handler, idpClients, h.AuthHeader(token)).Code)
	assert.Equal(t, http.StatusForbidden, h.JSONPost(idp.Handler, idpClients, newClientBody(), h.AuthHeader(token)).Code)
}

// The admin API is off unless the host turns it on.
func TestIDP_Admin_OffByDefault(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) { cfg.AdminAPI = false }})
	admin := idpAdmin(t, idp.Auth, idp.Handler)
	assert.Equal(t, http.StatusNotFound, h.JSONGet(idp.Handler, idpClients, h.AuthHeader(admin)).Code)
}

// An administrator registers an application, gets its secret once, and the
// application can then sign users in.
func TestIDP_Admin_ClientLifecycle(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	events := h.RecordEvents(idp.Auth, types.EventIDPClientCreated, types.EventIDPClientSecretRotated, types.EventIDPClientDeleted)
	admin := idpAdmin(t, idp.Auth, idp.Handler)
	_, ada := idpUser(t, idp.Handler, "ada@example.com")
	const redirect = "https://dashboard.example.test/callback"

	w := h.JSONPost(idp.Handler, idpClients, newClientBody(), h.AuthHeader(admin))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	created := envelopeData(t, w, http.StatusCreated)
	id, clientID, secret := created["id"].(string), created["client_id"].(string), created["client_secret"].(string)
	require.NotEmpty(t, secret, "the secret is shown when the client is created")
	assert.GreaterOrEqual(t, len(secret), 43)
	assert.Equal(t, true, created["require_pkce"], "PKCE is required unless the administrator says otherwise")
	assert.Equal(t, false, created["managed"])
	h.Nth(t, events, 1, func(data *types.IDPEventData) bool { return data.ClientID == clientID })

	got := envelopeData(t, h.JSONGet(idp.Handler, idpClients+"/"+id, h.AuthHeader(admin)), http.StatusOK)
	assert.Equal(t, "Dashboard", got["name"])
	assert.NotContains(t, got, "client_secret", "the secret is never shown again")

	// The stored row holds a digest, not the secret.
	stored, err := idp.Auth.Config().Storage.IDP().Clients().FindByID(context.Background(), id)
	require.NoError(t, err)
	assert.NotEqual(t, secret, stored.SecretHash)
	assert.NotContains(t, stored.SecretHash, secret)

	list := envelopeData(t, h.JSONGet(idp.Handler, idpClients+"?q=dash", h.AuthHeader(admin)), http.StatusOK)
	assert.Len(t, list["list"], 1)
	assert.EqualValues(t, 1, list["total"])
	list = envelopeData(t, h.JSONGet(idp.Handler, idpClients+"?managed=true", h.AuthHeader(admin)), http.StatusOK)
	require.Len(t, list["list"], 1)
	assert.Equal(t, h.IDPClientID, list["list"].([]interface{})[0].(map[string]interface{})["client_id"])

	require.Equal(t, http.StatusOK, signInTo(t, idp.Handler, ada, clientID, secret, redirect).Code)

	// Rotating the secret ends the old one at once.
	rotated := envelopeData(t, h.JSONPost(idp.Handler, idpClients+"/"+id+"/secret", nil, h.AuthHeader(admin)), http.StatusOK)
	newSecret := rotated["client_secret"].(string)
	require.NotEmpty(t, newSecret)
	assert.NotEqual(t, secret, newSecret)
	assert.Equal(t, "invalid_client", tokenError(t, signInTo(t, idp.Handler, ada, clientID, secret, redirect), http.StatusUnauthorized))
	require.Equal(t, http.StatusOK, signInTo(t, idp.Handler, ada, clientID, newSecret, redirect).Code)
	h.Nth(t, events, 1, func(data *types.IDPEventData) bool { return strings.Contains(data.Details, "rotated") })

	// Updating replaces the registration and keeps client_id and secret.
	body := newClientBody()
	body["name"] = "Dashboard v2"
	body["redirect_uris"] = []string{"https://dashboard.example.test/v2/callback"}
	body["client_id"] = "ignored"
	updated := envelopeData(t, h.JSONPut(idp.Handler, idpClients+"/"+id, body, h.AuthHeader(admin)), http.StatusOK)
	assert.Equal(t, "Dashboard v2", updated["name"])
	assert.Equal(t, clientID, updated["client_id"])
	assert.NotContains(t, updated, "client_secret")
	_, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirect)
	assert.Equal(t, http.StatusBadRequest, h.IDPAuthorize(idp.Handler, params).Code, "the old redirect URI is no longer registered")
	require.Equal(t, http.StatusOK, signInTo(t, idp.Handler, ada, clientID, newSecret, "https://dashboard.example.test/v2/callback").Code)

	// Disabling answers like an unknown client.
	body["disabled"] = true
	envelopeData(t, h.JSONPut(idp.Handler, idpClients+"/"+id, body, h.AuthHeader(admin)), http.StatusOK)
	params.Set("redirect_uri", "https://dashboard.example.test/v2/callback")
	assert.Equal(t, http.StatusBadRequest, h.IDPAuthorize(idp.Handler, params).Code)

	// Deleting removes the client and disconnects its users.
	require.Equal(t, http.StatusOK, h.JSONDelete(idp.Handler, idpClients+"/"+id, h.AuthHeader(admin)).Code)
	assert.Equal(t, http.StatusNotFound, h.JSONGet(idp.Handler, idpClients+"/"+id, h.AuthHeader(admin)).Code)
	grants := envelopeData(t, h.JSONGet(idp.Handler, h.IDPBase+"/grants", h.AuthHeader(ada)), http.StatusOK)
	assert.Empty(t, grants["list"])
	h.Nth(t, events, 1, func(data *types.IDPEventData) bool { return strings.Contains(data.Details, "deleted") })
}

func TestIDP_Admin_Validation(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	admin := idpAdmin(t, idp.Auth, idp.Handler)

	cases := map[string]func(map[string]interface{}){
		"no name":     func(b map[string]interface{}) { b["name"] = "  " },
		"no redirect": func(b map[string]interface{}) { b["redirect_uris"] = []string{} },
		"http redirect": func(b map[string]interface{}) {
			b["redirect_uris"] = []string{"http://dashboard.example.test/callback"}
		},
		"redirect fragment":   func(b map[string]interface{}) { b["redirect_uris"] = []string{"https://dashboard.example.test/cb#x"} },
		"javascript redirect": func(b map[string]interface{}) { b["redirect_uris"] = []string{"javascript:alert(1)"} },
		"unknown scope":       func(b map[string]interface{}) { b["scopes"] = []string{"openid", "admin"} },
		"no openid scope":     func(b map[string]interface{}) { b["scopes"] = []string{"email"} },
		"bad client id":       func(b map[string]interface{}) { b["client_id"] = "has spaces" },
		"bad logo":            func(b map[string]interface{}) { b["logo_uri"] = "javascript:alert(1)" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			body := newClientBody()
			change(body)
			w := h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin))
			data := envelopeData(t, w, http.StatusBadRequest)
			assert.Equal(t, string(types.ErrIDPInvalidClient), data["code"])
		})
	}

	t.Run("loopback http redirect is allowed", func(t *testing.T) {
		body := newClientBody()
		body["redirect_uris"] = []string{"http://localhost:3000/callback"}
		envelopeData(t, h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin)), http.StatusCreated)
	})
	t.Run("client id is unique", func(t *testing.T) {
		body := newClientBody()
		body["client_id"] = "chosen-id"
		created := envelopeData(t, h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin)), http.StatusCreated)
		assert.Equal(t, "chosen-id", created["client_id"])
		data := envelopeData(t, h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin)), http.StatusConflict)
		assert.Equal(t, string(types.ErrIDPClientExists), data["code"])
		// Also against a client declared in configuration.
		body["client_id"] = h.IDPClientID
		data = envelopeData(t, h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin)), http.StatusConflict)
		assert.Equal(t, string(types.ErrIDPClientExists), data["code"])
	})
	t.Run("malformed body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, idpClients, strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer "+admin)
		rec := httptest.NewRecorder()
		idp.Handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

// A client declared in configuration is read-only through the API.
func TestIDP_Admin_ManagedClientIsReadOnly(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	admin := idpAdmin(t, idp.Auth, idp.Handler)
	list := envelopeData(t, h.JSONGet(idp.Handler, idpClients+"?managed=true", h.AuthHeader(admin)), http.StatusOK)
	managed := list["list"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, true, managed["managed"])
	id := managed["id"].(string)

	for name, w := range map[string]*httptest.ResponseRecorder{
		"update": h.JSONPut(idp.Handler, idpClients+"/"+id, newClientBody(), h.AuthHeader(admin)),
		"delete": h.JSONDelete(idp.Handler, idpClients+"/"+id, h.AuthHeader(admin)),
		"rotate": h.JSONPost(idp.Handler, idpClients+"/"+id+"/secret", nil, h.AuthHeader(admin)),
	} {
		data := envelopeData(t, w, http.StatusConflict)
		assert.Equal(t, string(types.ErrIDPClientManaged), data["code"], name)
	}
}

// A public client has no secret and proves itself with PKCE alone.
func TestIDP_PublicClient(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	admin := idpAdmin(t, idp.Auth, idp.Handler)
	_, ada := idpUser(t, idp.Handler, "ada@example.com")
	const redirect = "https://spa.example.test/callback"

	body := map[string]interface{}{"name": "Single-page app", "redirect_uris": []string{redirect}, "public": true, "require_pkce": false}
	created := envelopeData(t, h.JSONPost(idp.Handler, idpClients, body, h.AuthHeader(admin)), http.StatusCreated)
	clientID := created["client_id"].(string)
	assert.NotContains(t, created, "client_secret")
	assert.Equal(t, true, created["require_pkce"], "a public client always requires PKCE")

	require.Equal(t, http.StatusOK, signInTo(t, idp.Handler, ada, clientID, "", redirect).Code)
	assert.Equal(t, "invalid_client", tokenError(t, signInTo(t, idp.Handler, ada, clientID, "a-secret-it-does-not-have", redirect), http.StatusUnauthorized))

	_, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirect)
	params.Del("code_challenge")
	params.Del("code_challenge_method")
	w := h.IDPAuthorize(idp.Handler, params)
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=invalid_request")

	rotate := h.JSONPost(idp.Handler, idpClients+"/"+created["id"].(string)+"/secret", nil, h.AuthHeader(admin))
	assert.Equal(t, string(types.ErrIDPInvalidClient), envelopeData(t, rotate, http.StatusBadRequest)["code"])

	// Turning it into a confidential client hands out a secret, once.
	body["public"] = false
	updated := envelopeData(t, h.JSONPut(idp.Handler, idpClients+"/"+created["id"].(string), body, h.AuthHeader(admin)), http.StatusOK)
	secret, _ := updated["client_secret"].(string)
	require.NotEmpty(t, secret)
	assert.Equal(t, "invalid_client", tokenError(t, signInTo(t, idp.Handler, ada, clientID, "", redirect), http.StatusUnauthorized))
	assert.Equal(t, http.StatusOK, signInTo(t, idp.Handler, ada, clientID, secret, redirect).Code)
}

// An older application that cannot send PKCE can be allowed to go without,
// and is then held to its redirect URI instead.
func TestIDP_ClientWithoutPKCE(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.Clients[0].AllowWithoutPKCE = true
	}})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	params := h.IDPAuthorizeParams("")
	params.Del("code_challenge")
	params.Del("code_challenge_method")

	code := h.IDPCode(t, idp.Handler, token, params)
	w := h.IDPTokenRequest(idp.Handler, url.Values{"grant_type": {"authorization_code"}, "code": {code}}, true)
	assert.Equal(t, "invalid_grant", tokenError(t, w, http.StatusBadRequest), "without PKCE the redirect URI must be repeated")

	code = h.IDPCode(t, idp.Handler, token, params)
	w = h.IDPTokenRequest(idp.Handler, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.IDPRedirectURI}, "code_verifier": {strings.Repeat("a", 43)}}, true)
	assert.Equal(t, "invalid_grant", tokenError(t, w, http.StatusBadRequest), "a verifier for a request that had no challenge is refused")

	code = h.IDPCode(t, idp.Handler, token, params)
	w = h.IDPTokenRequest(idp.Handler, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.IDPRedirectURI}}, true)
	assert.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
}

// Records of the flow are stored as digests: nothing read from the database
// can be redeemed.
func TestIDP_SecretsAtRest(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	verifier, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("scope", "openid offline_access")
	requestID := h.IDPRequestID(t, idp.Handler, params)
	code := h.IDPApprove(t, idp.Handler, token, requestID).Query().Get("code")
	response := h.IDPExchange(t, idp.Handler, code, verifier)

	tokens := idp.Auth.Config().Storage.Core().Tokens()
	for name, raw := range map[string]string{
		"request": requestID, "code": code,
		"access token": response["access_token"].(string), "refresh token": response["refresh_token"].(string),
	} {
		_, err := tokens.FindByToken(context.Background(), raw)
		assert.Error(t, err, "the %s must not be stored as it is handed out", name)
	}

	client, err := idp.Auth.Config().Storage.IDP().Clients().FindByClientID(context.Background(), h.IDPClientID)
	require.NoError(t, err)
	assert.NotEqual(t, h.IDPClientSecret, client.SecretHash)
}

// Deleting a user removes the record of the applications they approved.
func TestIDP_DeletedUserLosesGrants(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	ctx := context.Background()
	admin := idpAdmin(t, idp.Auth, idp.Handler)
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid offline_access")

	grants := idp.Auth.Config().Storage.IDP().Grants()
	count := func() int64 {
		_, total, err := grants.List(ctx, models.IDPGrantListOpts{ListingOpts: models.DefaultListingOpts(), UserID: userID})
		require.NoError(t, err)
		return total
	}
	require.EqualValues(t, 1, count())

	w := h.JSONDelete(idp.Handler, "/auth/admin/users/"+userID, h.AuthHeader(admin))
	require.Equal(t, http.StatusOK, w.Code, "delete user: %s", w.Body.String())

	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, response["access_token"].(string)).Code, "the tokens end with the account")
	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, response["refresh_token"].(string)), http.StatusBadRequest))
	// The grant is removed when the deletion event is delivered.
	require.Eventually(t, func() bool { return count() == 0 }, 3*time.Second, 20*time.Millisecond)
}
