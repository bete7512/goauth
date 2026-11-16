//go:build integration

package integration_test

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLogin hits the login endpoint and returns the IdP redirect and the binding cookie.
func startLogin(t *testing.T, handler http.Handler, query string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/keycloak/login"+query, nil))
	require.Equal(t, http.StatusFound, rec.Code, "login: %s", rec.Body.String())
	location := rec.Header().Get("Location")
	require.Contains(t, location, "https://idp.example.com/sso?")
	require.Contains(t, location, "SAMLRequest=")
	require.Contains(t, location, "Signature=", "requests are signed")
	var binding *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "goauth_saml_keycloak" {
			binding = c
		}
	}
	require.NotNil(t, binding, "binding cookie")
	require.True(t, binding.HttpOnly)
	require.Equal(t, http.SameSiteNoneMode, binding.SameSite, "cross-site POST needs SameSite=None")
	return location, binding
}

func postACS(handler http.Handler, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/keycloak/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestSAML_ProvidersAndMetadata(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	_, handler := h.SetupStatelessWithSAML(t, idp, nil)

	w := h.JSONGet(handler, "/auth/saml/providers")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := h.ParseJSON(t, w.Body)
	providers := body["data"].(map[string]interface{})["providers"].([]interface{})
	require.Len(t, providers, 1)
	assert.Equal(t, "http://localhost:8080/auth/saml/keycloak/login", providers[0].(map[string]interface{})["login_url"])

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/keycloak/metadata", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/samlmetadata+xml", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), `entityID="http://localhost:8080/auth/saml/keycloak/metadata"`)
	assert.Contains(t, rec.Body.String(), `Location="http://localhost:8080/auth/saml/keycloak/acs"`)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/unknown/metadata", nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSAML_FullLoginCreatesUserAndIssuesTokens(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	a, handler := h.SetupStatelessWithSAML(t, idp, nil)
	events := h.RecordEvents(a, types.EventAfterSAMLLogin)

	location, cookie := startLogin(t, handler, "")
	form := idp.Respond(t, location)
	require.Equal(t, cookie.Value, form.Get("RelayState"), "RelayState carries the request ID")

	rec := postACS(handler, form, cookie)
	require.Equal(t, http.StatusOK, rec.Code, "acs: %s", rec.Body.String())
	body := h.ParseJSON(t, rec.Body)
	data := body["data"].(map[string]interface{})
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, true, data["is_new_user"])
	assert.Equal(t, "keycloak", data["provider"])
	user := data["user"].(map[string]interface{})
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, true, user["email_verified"])
	assert.Equal(t, "Alice", user["first_name"])

	// The issued access token works against the core profile endpoint.
	me := h.Me(t, handler, data["access_token"].(string))
	assert.Equal(t, "alice@example.com", me["email"])

	h.Nth(t, events, 1, func(d *types.SAMLLoginEventData) bool { return d.NameID == "saml-subject-1" && d.IsNewUser })

	// A second login with the same subject reuses the user.
	location, cookie = startLogin(t, handler, "")
	rec = postACS(handler, idp.Respond(t, location), cookie)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	data = h.ParseJSON(t, rec.Body)["data"].(map[string]interface{})
	assert.Equal(t, false, data["is_new_user"])
	assert.Equal(t, user["id"], data["user"].(map[string]interface{})["id"])
}

func TestSAML_RedirectWithFragment(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	_, handler := h.SetupStatelessWithSAML(t, idp, func(c *config.SAMLModuleConfig) {
		c.DefaultRedirectURL = "http://localhost:3000/auth/callback"
	})

	location, cookie := startLogin(t, handler, "?redirect_uri="+url.QueryEscape("http://localhost:3000/after-sso"))
	rec := postACS(handler, idp.Respond(t, location), cookie)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	target, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/after-sso", target.Path)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	assert.NotEmpty(t, fragment.Get("access_token"))
	assert.Equal(t, "true", fragment.Get("is_new_user"))

	// A redirect_uri on a foreign origin is refused after authentication.
	location, cookie = startLogin(t, handler, "?redirect_uri="+url.QueryEscape("https://evil.example.com/steal"))
	rec = postACS(handler, idp.Respond(t, location), cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid_redirect_url")

	// A path on this server is a first-party page: cookies, and no tokens in
	// the URL.
	location, cookie = startLogin(t, handler, "?redirect_uri="+url.QueryEscape("/admin/login/done?next=%2Fadmin"))
	rec = postACS(handler, idp.Respond(t, location), cookie)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, "/admin/login/done?next=%2Fadmin", rec.Header().Get("Location"))
	var names []string
	for _, c := range rec.Result().Cookies() {
		names = append(names, c.Name)
	}
	assert.Contains(t, strings.Join(names, " "), "goauth_access_")

	// A path that could leave the site is not one.
	location, cookie = startLogin(t, handler, "?redirect_uri="+url.QueryEscape("//evil.example.com/steal"))
	rec = postACS(handler, idp.Respond(t, location), cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

func TestSAML_ACSRejectsMissingCookieReplayAndTampering(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	_, handler := h.SetupStatelessWithSAML(t, idp, nil)

	location, cookie := startLogin(t, handler, "")
	form := idp.Respond(t, location)

	// No binding cookie: the browser that posts is not the one that started.
	rec := postACS(handler, form, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLInvalidRequest))

	// Wrong cookie value.
	rec = postACS(handler, form, &http.Cookie{Name: cookie.Name, Value: "id-other"})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// The genuine response works once...
	rec = postACS(handler, form, cookie)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// ...and is refused when replayed.
	rec = postACS(handler, form, cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLInvalidRequest))

	// A tampered envelope breaks the signature. The pending request is
	// consumed before verification, so one request accepts exactly one post.
	location, cookie = startLogin(t, handler, "")
	form = idp.Respond(t, location)
	tampered := url.Values{}
	tampered.Set("RelayState", form.Get("RelayState"))
	tampered.Set("SAMLResponse", form.Get("SAMLResponse")[:len(form.Get("SAMLResponse"))-8]+"AAAAAAAA")
	rec = postACS(handler, tampered, cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLInvalidResponse))
	assert.NotContains(t, rec.Body.String(), "signature", "the cause stays in the log")
	rec = postACS(handler, form, cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "the genuine response no longer has a pending request")
}

func TestSAML_IDPInitiated(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	_, handler := h.SetupStatelessWithSAML(t, idp, nil)

	// Build an unsolicited response: start a login to get a valid redirect,
	// then drop the RelayState the IdP echoed.
	location, _ := startLogin(t, handler, "")
	form := idp.Respond(t, location)
	form.Del("RelayState")
	rec := postACS(handler, form, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLIDPInitiatedDisabled))

	idp2 := h.NewFakeSAMLIdP(t)
	_, handler2 := h.SetupStatelessWithSAML(t, idp2, func(c *config.SAMLModuleConfig) {
		c.Providers["keycloak"].AllowIDPInitiated = true
	})
	rec = httptest.NewRecorder()
	idp2.IDP.ServeIDPInitiated(rec, httptest.NewRequest(http.MethodGet, "https://idp.example.com/idp-initiated", nil), "http://localhost:8080/auth/saml/keycloak/metadata", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	unsolicited := url.Values{}
	for _, field := range []string{"SAMLResponse"} {
		start := strings.Index(rec.Body.String(), `name="`+field+`" value="`) + len(`name="`+field+`" value="`)
		end := strings.Index(rec.Body.String()[start:], `"`)
		unsolicited.Set(field, html.UnescapeString(rec.Body.String()[start:start+end]))
	}
	rec = postACS(handler2, unsolicited, nil)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestSAML_SignupDisabledAndLinking(t *testing.T) {
	idp := h.NewFakeSAMLIdP(t)
	_, handler := h.SetupStatelessWithSAML(t, idp, func(c *config.SAMLModuleConfig) {
		c.AllowSignup = false
	})
	location, cookie := startLogin(t, handler, "")
	rec := postACS(handler, idp.Respond(t, location), cookie)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLSignupDisabled))

	// An existing local account with the same email: refused by default...
	idp2 := h.NewFakeSAMLIdP(t)
	_, handler2 := h.SetupStatelessWithSAML(t, idp2, nil)
	h.Signup(t, handler2, "alice@example.com", "Test1234", "Alice Local")
	location, cookie = startLogin(t, handler2, "")
	rec = postACS(handler2, idp2.Respond(t, location), cookie)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), string(types.ErrSAMLAccountLinkingDisabled))

	// ...and linked when allowed.
	idp3 := h.NewFakeSAMLIdP(t)
	_, handler3 := h.SetupStatelessWithSAML(t, idp3, func(c *config.SAMLModuleConfig) { c.AllowAccountLinking = true })
	local := h.Signup(t, handler3, "alice@example.com", "Test1234", "Alice Local")
	location, cookie = startLogin(t, handler3, "")
	rec = postACS(handler3, idp3.Respond(t, location), cookie)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	data := h.ParseJSON(t, rec.Body)["data"].(map[string]interface{})
	assert.Equal(t, false, data["is_new_user"])
	localUser := local["data"].(map[string]interface{})["user"].(map[string]interface{})
	assert.Equal(t, localUser["id"], data["user"].(map[string]interface{})["id"])
}
