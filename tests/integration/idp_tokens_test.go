//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/csrf"
	idpmodule "github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idpSignIn signs the user in to the default client and returns the token
// response. scope is the requested scope.
func idpSignIn(t *testing.T, handler http.Handler, token, scope string) map[string]interface{} {
	t.Helper()
	verifier, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("scope", scope)
	return h.IDPExchange(t, handler, h.IDPCode(t, handler, token, params), verifier)
}

// userInfo calls the UserInfo endpoint with a bearer token.
func userInfo(handler http.Handler, accessToken string) *httptest.ResponseRecorder {
	return h.JSONGet(handler, h.IDPBase+"/userinfo", h.AuthHeader(accessToken))
}

// tokenError asserts a token endpoint error and returns its code.
func tokenError(t *testing.T, w *httptest.ResponseRecorder, status int) string {
	t.Helper()
	require.Equal(t, status, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	body := h.ParseJSON(t, w.Body)
	code, _ := body["error"].(string)
	require.NotEmpty(t, code, "an OAuth error object is expected: %v", body)
	return code
}

func refreshRequest(handler http.Handler, refreshToken string) *httptest.ResponseRecorder {
	return h.IDPTokenRequest(handler, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}, true)
}

// A code is redeemed once. A second redemption fails and ends what the
// first one produced, because a code seen twice has leaked.
func TestIDP_Code_SingleUse(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	verifier, challenge := h.PKCEPair(t)
	code := h.IDPCode(t, idp.Handler, token, h.IDPAuthorizeParams(challenge))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.IDPRedirectURI}, "code_verifier": {verifier}}

	first := h.IDPTokenRequest(idp.Handler, form, true)
	require.Equal(t, http.StatusOK, first.Code, "body: %s", first.Body.String())
	accessToken := h.ParseJSON(t, first.Body)["access_token"].(string)
	require.Equal(t, http.StatusOK, userInfo(idp.Handler, accessToken).Code)

	assert.Equal(t, "invalid_grant", tokenError(t, h.IDPTokenRequest(idp.Handler, form, true), http.StatusBadRequest))
	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, accessToken).Code, "the tokens of the first redemption are ended")
}

// A code is bound to its client, its redirect URI and its PKCE challenge,
// and a failed attempt burns it.
func TestIDP_Code_Bindings(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.Clients = append(cfg.Clients, config.IDPClientConfig{
			ClientID: "other-app", Secret: "other-app-secret-0123456789abcdef0123456789", Name: "Other",
			RedirectURIs: []string{h.IDPRedirectURI},
		})
	}})
	_, token := idpUser(t, idp.Handler, "ada@example.com")

	cases := map[string]func(form url.Values, req *http.Request){
		"wrong verifier":   func(form url.Values, _ *http.Request) { form.Set("code_verifier", strings.Repeat("a", 43)) },
		"missing verifier": func(form url.Values, _ *http.Request) { form.Del("code_verifier") },
		"wrong redirect":   func(form url.Values, _ *http.Request) { form.Set("redirect_uri", "https://rp.example.test/other") },
		"another client": func(_ url.Values, req *http.Request) {
			req.SetBasicAuth("other-app", "other-app-secret-0123456789abcdef0123456789")
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			verifier, challenge := h.PKCEPair(t)
			code := h.IDPCode(t, idp.Handler, token, h.IDPAuthorizeParams(challenge))
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.IDPRedirectURI}, "code_verifier": {verifier}}
			good := url.Values{}
			for key, values := range form {
				good[key] = values
			}
			req := httptest.NewRequest(http.MethodPost, h.IDPBase+"/token", nil)
			req.SetBasicAuth(h.IDPClientID, h.IDPClientSecret)
			change(form, req)
			req.Body = http.NoBody
			body := httptest.NewRequest(http.MethodPost, h.IDPBase+"/token", strings.NewReader(form.Encode()))
			body.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			body.Header.Set("Authorization", req.Header.Get("Authorization"))
			w := httptest.NewRecorder()
			idp.Handler.ServeHTTP(w, body)
			assert.Equal(t, "invalid_grant", tokenError(t, w, http.StatusBadRequest))

			// The right client with the right values afterwards: the code
			// was burned by the failed attempt, unless another client made
			// it, which must change nothing.
			retry := h.IDPTokenRequest(idp.Handler, good, true)
			if name == "another client" {
				assert.Equal(t, http.StatusOK, retry.Code, "another client's attempt must not spend the code: %s", retry.Body.String())
			} else {
				assert.Equal(t, "invalid_grant", tokenError(t, retry, http.StatusBadRequest))
			}
		})
	}
}

func TestIDP_Token_ClientAuthentication(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	newForm := func() url.Values {
		verifier, challenge := h.PKCEPair(t)
		code := h.IDPCode(t, idp.Handler, token, h.IDPAuthorizeParams(challenge))
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.IDPRedirectURI}, "code_verifier": {verifier}}
	}

	t.Run("secret in the form", func(t *testing.T) {
		form := newForm()
		form.Set("client_id", h.IDPClientID)
		form.Set("client_secret", h.IDPClientSecret)
		w := h.IDPTokenRequest(idp.Handler, form, false)
		assert.Equal(t, http.StatusOK, w.Code, "client_secret_post: %s", w.Body.String())
	})
	t.Run("wrong secret", func(t *testing.T) {
		form := newForm()
		form.Set("client_id", h.IDPClientID)
		form.Set("client_secret", "not-the-secret")
		w := h.IDPTokenRequest(idp.Handler, form, false)
		assert.Equal(t, "invalid_client", tokenError(t, w, http.StatusUnauthorized))
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic")
	})
	t.Run("no credentials", func(t *testing.T) {
		form := newForm()
		form.Set("client_id", h.IDPClientID)
		assert.Equal(t, "invalid_client", tokenError(t, h.IDPTokenRequest(idp.Handler, form, false), http.StatusUnauthorized))
	})
	t.Run("two methods at once", func(t *testing.T) {
		form := newForm()
		form.Set("client_secret", h.IDPClientSecret)
		assert.Equal(t, "invalid_request", tokenError(t, h.IDPTokenRequest(idp.Handler, form, true), http.StatusBadRequest))
	})
	t.Run("unknown client", func(t *testing.T) {
		form := newForm()
		form.Set("client_id", "nobody")
		form.Set("client_secret", h.IDPClientSecret)
		assert.Equal(t, "invalid_client", tokenError(t, h.IDPTokenRequest(idp.Handler, form, false), http.StatusUnauthorized))
	})
	t.Run("unsupported grant type", func(t *testing.T) {
		w := h.IDPTokenRequest(idp.Handler, url.Values{"grant_type": {"client_credentials"}}, true)
		assert.Equal(t, "unsupported_grant_type", tokenError(t, w, http.StatusBadRequest))
	})
	t.Run("json body", func(t *testing.T) {
		w := h.JSONPost(idp.Handler, h.IDPBase+"/token", map[string]interface{}{"grant_type": "authorization_code"})
		assert.Equal(t, "invalid_request", tokenError(t, w, http.StatusBadRequest))
	})
}

// UserInfo releases what the granted scopes allow and nothing else.
func TestIDP_UserInfo(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	userID, token := idpUser(t, idp.Handler, "ada@example.com")

	full := idpSignIn(t, idp.Handler, token, "openid profile email")["access_token"].(string)
	w := userInfo(idp.Handler, full)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	claims := h.ParseJSON(t, w.Body)
	assert.Equal(t, userID, claims["sub"])
	assert.Equal(t, "ada@example.com", claims["email"])
	assert.Equal(t, "Ada Lovelace", claims["name"])
	assert.NotContains(t, claims, "password")

	minimal := idpSignIn(t, idp.Handler, token, "openid")["access_token"].(string)
	w = userInfo(idp.Handler, minimal)
	require.Equal(t, http.StatusOK, w.Code)
	claims = h.ParseJSON(t, w.Body)
	assert.Equal(t, userID, claims["sub"])
	assert.NotContains(t, claims, "email")
	assert.NotContains(t, claims, "name")

	t.Run("token in a form body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, h.IDPBase+"/userinfo", strings.NewReader(url.Values{"access_token": {full}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		idp.Handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	})
	t.Run("token in the URL is not accepted", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, h.JSONGet(idp.Handler, h.IDPBase+"/userinfo?access_token="+full).Code)
	})
	for name, bearer := range map[string]string{
		"no token": "", "unknown token": "not-a-token",
		// GoAuth's own access token and the ID token are not UserInfo credentials.
		"first-party token": token,
	} {
		t.Run(name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if bearer == "" {
				rec = h.JSONGet(idp.Handler, h.IDPBase+"/userinfo")
			} else {
				rec = userInfo(idp.Handler, bearer)
			}
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			assert.Equal(t, "invalid_token", h.ParseJSON(t, rec.Body)["error"])
		})
	}
}

// The tokens handed to another application are not credentials for GoAuth's
// own endpoints.
func TestIDP_IssuedTokensAreNotFirstPartyCredentials(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid profile email offline_access")

	for name, credential := range map[string]string{
		"id token": response["id_token"].(string), "access token": response["access_token"].(string), "refresh token": response["refresh_token"].(string),
	} {
		assert.Equal(t, http.StatusUnauthorized, h.JSONGet(idp.Handler, "/auth/me", h.AuthHeader(credential)).Code, name)
	}
	w := h.JSONPost(idp.Handler, "/auth/refresh", map[string]interface{}{"refresh_token": response["refresh_token"]})
	assert.NotEqual(t, http.StatusOK, w.Code, "an application's refresh token must not refresh a GoAuth session")
}

// A refresh token is issued only with offline_access, rotates on every use,
// and keeps the sign-in time and scopes of the original sign-in.
func TestIDP_Refresh_Rotates(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	userID, token := idpUser(t, idp.Handler, "ada@example.com")

	assert.NotContains(t, idpSignIn(t, idp.Handler, token, "openid email"), "refresh_token")

	first := idpSignIn(t, idp.Handler, token, "openid email offline_access")
	refreshToken := first["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	w := refreshRequest(idp.Handler, refreshToken)
	require.Equal(t, http.StatusOK, w.Code, "refresh: %s", w.Body.String())
	second := h.ParseJSON(t, w.Body)
	assert.NotEqual(t, refreshToken, second["refresh_token"], "the refresh token rotates")
	assert.NotEqual(t, first["access_token"], second["access_token"])
	assert.Equal(t, "openid email offline_access", second["scope"])
	assert.Equal(t, http.StatusOK, userInfo(idp.Handler, second["access_token"].(string)).Code)

	provider, err := oidc.NewProvider(context.Background(), idp.Issuer)
	require.NoError(t, err)
	verifier := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID})
	original, err := verifier.Verify(context.Background(), first["id_token"].(string))
	require.NoError(t, err)
	refreshed, err := verifier.Verify(context.Background(), second["id_token"].(string))
	require.NoError(t, err)
	assert.Equal(t, userID, refreshed.Subject)
	assert.Empty(t, refreshed.Nonce, "a refreshed ID token carries no nonce")
	var before, after struct {
		AuthTime int64 `json:"auth_time"`
	}
	require.NoError(t, original.Claims(&before))
	require.NoError(t, refreshed.Claims(&after))
	assert.Equal(t, before.AuthTime, after.AuthTime, "auth_time stays the original sign-in")

	t.Run("narrowing scopes", func(t *testing.T) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second["refresh_token"].(string)}, "scope": {"openid"}}
		w := h.IDPTokenRequest(idp.Handler, form, true)
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		narrowed := h.ParseJSON(t, w.Body)
		assert.Equal(t, "openid", narrowed["scope"])
		assert.NotContains(t, h.ParseJSON(t, userInfo(idp.Handler, narrowed["access_token"].(string)).Body), "email")

		form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {narrowed["refresh_token"].(string)}, "scope": {"openid profile"}}
		assert.Equal(t, "invalid_scope", tokenError(t, h.IDPTokenRequest(idp.Handler, form, true), http.StatusBadRequest))
	})
}

// A rotated refresh token presented again inside the leeway is a retry: it
// fails and nothing else happens.
func TestIDP_Refresh_RetryInsideLeeway(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	refreshToken := idpSignIn(t, idp.Handler, token, "openid offline_access")["refresh_token"].(string)

	w := refreshRequest(idp.Handler, refreshToken)
	require.Equal(t, http.StatusOK, w.Code)
	rotated := h.ParseJSON(t, w.Body)["refresh_token"].(string)

	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, refreshToken), http.StatusBadRequest))
	assert.Equal(t, http.StatusOK, refreshRequest(idp.Handler, rotated).Code, "the application stays connected")
}

// Outside the leeway it is a copied token: the application is disconnected
// and the event is reported.
func TestIDP_Refresh_ReuseEndsTheGrant(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.RefreshTokenReuseLeeway = -1
	}})
	events := h.RecordEvents(idp.Auth, types.EventIDPTokenReuseDetected)
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	refreshToken := idpSignIn(t, idp.Handler, token, "openid offline_access")["refresh_token"].(string)

	w := refreshRequest(idp.Handler, refreshToken)
	require.Equal(t, http.StatusOK, w.Code)
	rotated := h.ParseJSON(t, w.Body)

	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, refreshToken), http.StatusBadRequest))
	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, rotated["refresh_token"].(string)), http.StatusBadRequest), "the whole family is ended")
	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, rotated["access_token"].(string)).Code)

	reported := h.Nth(t, events, 1, func(data *types.IDPEventData) bool { return data.UserID == userID })
	assert.Equal(t, h.IDPClientID, reported.ClientID)

	w = h.JSONGet(idp.Handler, h.IDPBase+"/grants", h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["list"], "the application is no longer connected")
}

// Signing out of the host application leaves connected applications alone;
// changing the password ends their tokens.
func TestIDP_SignOutKeepsAndPasswordChangeEndsTokens(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid email offline_access")
	accessToken, refreshToken := response["access_token"].(string), response["refresh_token"].(string)

	require.Equal(t, http.StatusOK, h.JSONPost(idp.Handler, "/auth/logout", nil, h.AuthHeader(token)).Code)
	assert.Equal(t, http.StatusOK, userInfo(idp.Handler, accessToken).Code, "signing out does not disconnect applications")
	w := refreshRequest(idp.Handler, refreshToken)
	require.Equal(t, http.StatusOK, w.Code, "refresh after sign-out: %s", w.Body.String())
	refreshed := h.ParseJSON(t, w.Body)

	token, _ = h.Login(t, idp.Handler, "ada@example.com", "Test1234")
	w = h.JSONPut(idp.Handler, "/auth/change-password", map[string]interface{}{
		"old_password": "Test1234", "new_password": "Changed5678",
	}, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "change password: %s", w.Body.String())

	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, refreshed["access_token"].(string)).Code)
	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, refreshed["refresh_token"].(string)), http.StatusBadRequest))

	// Consent survives: the user signs in again without being asked.
	token, _ = h.Login(t, idp.Handler, "ada@example.com", "Changed5678")
	_, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("scope", "openid email offline_access")
	assert.Equal(t, false, consentDetails(t, idp.Handler, token, h.IDPRequestID(t, idp.Handler, params))["consent_required"])
}

// A user who may no longer sign in gets nothing from tokens issued earlier.
func TestIDP_DeactivatedUser(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid offline_access")

	users := idp.Auth.Config().Storage.Core().Users()
	user, err := users.FindByID(context.Background(), userID)
	require.NoError(t, err)
	user.Active = false
	require.NoError(t, users.Update(context.Background(), user))

	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, response["access_token"].(string)).Code)
	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, response["refresh_token"].(string)), http.StatusBadRequest))
}

// Users see the applications they are connected to and can disconnect them.
func TestIDP_Grants_ListAndRevoke(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	_, ada := idpUser(t, idp.Handler, "ada@example.com")
	_, grace := idpUser(t, idp.Handler, "grace@example.com")
	response := idpSignIn(t, idp.Handler, ada, "openid email offline_access")
	idpSignIn(t, idp.Handler, ada, "openid profile")

	w := h.JSONGet(idp.Handler, h.IDPBase+"/grants", h.AuthHeader(ada))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	list := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["list"].([]interface{})
	require.Len(t, list, 1, "one grant per application, however often the user signs in")
	grant := list[0].(map[string]interface{})
	assert.Equal(t, h.IDPClientID, grant["client_id"])
	assert.Equal(t, "Test Application", grant["client_name"])
	assert.ElementsMatch(t, []interface{}{"openid", "email", "offline_access", "profile"}, grant["scopes"])
	grantID := grant["id"].(string)

	w = h.JSONGet(idp.Handler, h.IDPBase+"/grants", h.AuthHeader(grace))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["list"])

	assert.Equal(t, http.StatusNotFound, h.JSONDelete(idp.Handler, h.IDPBase+"/grants/"+grantID, h.AuthHeader(grace)).Code, "another user's grant")
	assert.Equal(t, http.StatusUnauthorized, h.JSONDelete(idp.Handler, h.IDPBase+"/grants/"+grantID).Code)
	require.Equal(t, http.StatusOK, userInfo(idp.Handler, response["access_token"].(string)).Code)

	require.Equal(t, http.StatusOK, h.JSONDelete(idp.Handler, h.IDPBase+"/grants/"+grantID, h.AuthHeader(ada)).Code)
	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, response["access_token"].(string)).Code)
	assert.Equal(t, "invalid_grant", tokenError(t, refreshRequest(idp.Handler, response["refresh_token"].(string)), http.StatusBadRequest))
	assert.Equal(t, http.StatusNotFound, h.JSONDelete(idp.Handler, h.IDPBase+"/grants/"+grantID, h.AuthHeader(ada)).Code)

	// Consent went with the grant.
	_, challenge := h.PKCEPair(t)
	assert.Equal(t, true, consentDetails(t, idp.Handler, ada, h.IDPRequestID(t, idp.Handler, h.IDPAuthorizeParams(challenge)))["consent_required"])
}

// A host can disconnect every application of a user.
func TestIDP_RevokeUserGrants(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid")

	revoked, err := idpmodule.RevokeUserGrants(context.Background(), idp.Module, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, revoked)
	assert.Equal(t, http.StatusUnauthorized, userInfo(idp.Handler, response["access_token"].(string)).Code)
}

// The host's claims function adds claims to the ID token and to UserInfo,
// and cannot replace the ones the module sets.
func TestIDP_CustomClaims(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Module: func(cfg *config.IDPModuleConfig) {
		cfg.Claims = func(_ context.Context, request config.IDPClaimsRequest) (map[string]interface{}, error) {
			return map[string]interface{}{"groups": []string{"engineering"}, "sub": "someone-else", "client": request.ClientID}, nil
		}
	}})
	userID, token := idpUser(t, idp.Handler, "ada@example.com")
	response := idpSignIn(t, idp.Handler, token, "openid")

	provider, err := oidc.NewProvider(context.Background(), idp.Issuer)
	require.NoError(t, err)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID}).Verify(context.Background(), response["id_token"].(string))
	require.NoError(t, err)
	assert.Equal(t, userID, idToken.Subject, "sub cannot be replaced")
	var claims struct {
		Groups []string `json:"groups"`
		Client string   `json:"client"`
	}
	require.NoError(t, idToken.Claims(&claims))
	assert.Equal(t, []string{"engineering"}, claims.Groups)
	assert.Equal(t, h.IDPClientID, claims.Client)

	info := h.ParseJSON(t, userInfo(idp.Handler, response["access_token"].(string)).Body)
	assert.Equal(t, userID, info["sub"])
	assert.Equal(t, []interface{}{"engineering"}, info["groups"])
}

// The token and UserInfo endpoints are called by servers, which hold no
// CSRF token; the consent decision is made from a page and needs one.
func TestIDP_WithCSRFModule(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{Use: []config.Module{csrf.New(nil)}})
	_, challenge := h.PKCEPair(t)
	requestID := h.IDPRequestID(t, idp.Handler, h.IDPAuthorizeParams(challenge))

	w := h.IDPTokenRequest(idp.Handler, url.Values{"grant_type": {"authorization_code"}, "code": {"nothing"}}, true)
	assert.Equal(t, "invalid_grant", tokenError(t, w, http.StatusBadRequest), "the token endpoint is not behind CSRF protection")

	req := httptest.NewRequest(http.MethodPost, h.IDPBase+"/userinfo", strings.NewReader("access_token=nothing"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	idp.Handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "UserInfo by POST is not behind CSRF protection")

	w = h.JSONPost(idp.Handler, h.IDPBase+"/consent/"+requestID+"/approve", nil)
	assert.Equal(t, http.StatusForbidden, w.Code, "the consent decision is behind CSRF protection")
}
