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
	"github.com/bete7512/goauth/pkg/modules/csrf"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The module's own sign-in and consent page: what a host gets when it names
// no page of its frontend.

const pagePassword = "Test1234"

// pageRequestID reads the request a page address is for.
func pageRequestID(t *testing.T, page string) string {
	t.Helper()
	parsed, err := url.Parse(page)
	require.NoError(t, err)
	return parsed.Query().Get("request_id")
}

// pageSignIn submits the page's sign-in form.
func pageSignIn(b *h.Browser, requestID, email, password string) *http.Response {
	return b.Post(h.IDPBase+"/consent/signin", url.Values{"request_id": {requestID}, "email": {email}, "password": {password}}).Result()
}

// hiddenValue reads a hidden form field from a page.
func hiddenValue(t *testing.T, page, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	start := strings.Index(page, marker)
	require.GreaterOrEqual(t, start, 0, "the page has no %s field", name)
	start += len(marker)
	return page[start : start+strings.IndexByte(page[start:], '"')]
}

// clientRedirect asserts that a response sends the browser back to the
// client application and returns the parameters it carries.
func clientRedirect(t *testing.T, status int, location string) url.Values {
	t.Helper()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, status)
	require.True(t, strings.HasPrefix(location, h.IDPRedirectURI+"?"), "expected a redirect to the client, got %s", location)
	target, err := url.Parse(location)
	require.NoError(t, err)
	return target.Query()
}

// A user who is not signed in signs in on the page, approves, and the
// client redeems the code. The next sign-in to the same application asks
// nothing.
func TestIDPPage_SignInAndApprove(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	verifier, challenge := h.PKCEPair(t)
	b := h.NewBrowser(t, idp.Handler)

	b.Site = "cross-site" // the client application sent the browser here
	page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	requestID := pageRequestID(t, page)
	w := b.Get(page)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "<h1>Sign in</h1>")
	assert.Contains(t, body, "Test Application")
	assert.Contains(t, body, "Acme", "the page says whose account is asked for")
	assert.Contains(t, body, "rp.example.test")
	assert.NotContains(t, body, "<script", "the page runs no script")
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	policy := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, policy, "default-src 'none'")
	assert.Contains(t, policy, "frame-ancestors 'none'")
	assert.Contains(t, policy, "form-action 'self' https://rp.example.test;", "the way back to the client is allowed, and nowhere else")

	b.Site = "same-origin" // from here on the page's own forms
	wrong := pageSignIn(b, requestID, "ada@example.com", "not-the-password")
	assert.Equal(t, http.StatusUnprocessableEntity, wrong.StatusCode)
	assert.Empty(t, b.Cookies)

	signedIn := pageSignIn(b, requestID, "ada@example.com", pagePassword)
	require.Equal(t, http.StatusSeeOther, signedIn.StatusCode)
	assert.Equal(t, page, signedIn.Header.Get("Location"))
	assert.NotEmpty(t, b.Cookies, "signing in on the page signs the browser in to the application")

	w = b.Get(page)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body = w.Body.String()
	assert.Contains(t, body, "Sign in to Test Application")
	assert.Contains(t, body, "ada@example.com")
	assert.Contains(t, body, "Confirm who you are")
	assert.Contains(t, body, "See your email address")
	userID := hiddenValue(t, body, "user")

	w = b.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "user": {userID}, "decision": {"approve"}})
	redirect := clientRedirect(t, w.Code, w.Header().Get("Location"))
	assert.Equal(t, "state-123", redirect.Get("state"))
	assert.Equal(t, idp.Issuer, redirect.Get("iss"))
	require.NotEmpty(t, redirect.Get("code"))

	tokens := h.IDPExchange(t, idp.Handler, redirect.Get("code"), verifier)
	provider, err := oidc.NewProvider(context.Background(), idp.Issuer)
	require.NoError(t, err)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.IDPClientID}).Verify(context.Background(), tokens["id_token"].(string))
	require.NoError(t, err)
	assert.Equal(t, userID, idToken.Subject)

	// The decision is single use.
	w = b.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "user": {userID}, "decision": {"approve"}})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "This sign-in has expired")

	// Signed in and already approved: straight back to the application.
	b.Site = "cross-site"
	w = b.Get(h.IDPPage(t, b, h.IDPAuthorizeParams(challenge)))
	assert.NotEmpty(t, clientRedirect(t, w.Code, w.Header().Get("Location")).Get("code"))
}

// The page signs in whoever the application's cookies say: a browser that
// is signed in to the application already goes straight to the question.
func TestIDPPage_UsesTheApplicationsSession(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Module: func(cfg *config.IDPModuleConfig) {
		cfg.Clients = append(cfg.Clients, config.IDPClientConfig{
			ClientID: "ours", Secret: h.IDPClientSecret, Name: "Our Other Product",
			RedirectURIs: []string{h.IDPRedirectURI}, SkipConsent: true,
		})
	}})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	_, challenge := h.PKCEPair(t)

	b := h.NewBrowser(t, idp.Handler)
	// The application's own login route, with cookies.
	w := b.PostJSON("/auth/login", `{"email":"ada@example.com","password":"`+pagePassword+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEmpty(t, b.Cookies)

	w = b.Get(h.IDPPage(t, b, h.IDPAuthorizeParams(challenge)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Sign in to Test Application")
	assert.NotContains(t, w.Body.String(), `name="password"`)

	// An application the host runs itself asks nothing.
	params := h.IDPAuthorizeParams(challenge)
	params.Set("client_id", "ours")
	w = b.Get(h.IDPPage(t, b, params))
	assert.NotEmpty(t, clientRedirect(t, w.Code, w.Header().Get("Location")).Get("code"))

	// "Use another account" shows the sign-in form without signing out.
	page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	w = b.Get(page + "&switch=1")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="password"`)
	assert.NotEmpty(t, b.Cookies)
}

// Cancelling goes back to the client with access_denied, whether or not
// anyone signed in.
func TestIDPPage_Cancel(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	_, challenge := h.PKCEPair(t)

	signedOut := h.NewBrowser(t, idp.Handler)
	requestID := pageRequestID(t, h.IDPPage(t, signedOut, h.IDPAuthorizeParams(challenge)))
	w := signedOut.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "decision": {"deny"}})
	redirect := clientRedirect(t, w.Code, w.Header().Get("Location"))
	assert.Equal(t, "access_denied", redirect.Get("error"))
	assert.Equal(t, "state-123", redirect.Get("state"))
	assert.Empty(t, redirect.Get("code"))

	signedIn := h.NewBrowser(t, idp.Handler)
	requestID = pageRequestID(t, h.IDPPage(t, signedIn, h.IDPAuthorizeParams(challenge)))
	require.Equal(t, http.StatusSeeOther, pageSignIn(signedIn, requestID, "ada@example.com", pagePassword).StatusCode)
	w = signedIn.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "decision": {"deny"}})
	assert.Equal(t, "access_denied", clientRedirect(t, w.Code, w.Header().Get("Location")).Get("error"))

	// Nobody may approve without signing in.
	requestID = pageRequestID(t, h.IDPPage(t, signedOut, h.IDPAuthorizeParams(challenge)))
	w = signedOut.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "decision": {"approve"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, h.IDPBase+"/consent?request_id="+requestID, w.Header().Get("Location"), "back to the page, which asks to sign in")
}

// The answer counts for the account the question was put to.
func TestIDPPage_AnswerIsBoundToTheAccountAsked(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	h.Signup(t, idp.Handler, "grace@example.com", pagePassword, "Grace Hopper")
	_, challenge := h.PKCEPair(t)

	b := h.NewBrowser(t, idp.Handler)
	page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	requestID := pageRequestID(t, page)
	require.Equal(t, http.StatusSeeOther, pageSignIn(b, requestID, "ada@example.com", pagePassword).StatusCode)
	adaID := hiddenValue(t, b.Get(page).Body.String(), "user")

	// Another tab signs the browser in as someone else before the answer.
	require.Equal(t, http.StatusSeeOther, pageSignIn(b, requestID, "grace@example.com", pagePassword).StatusCode)
	w := b.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "user": {adaID}, "decision": {"approve"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, page, w.Header().Get("Location"), "the question is asked again")
	body := b.Get(page).Body.String()
	assert.Contains(t, body, "grace@example.com")
	assert.NotContains(t, body, "ada@example.com")
}

// A sign-in that needs a second factor asks for it on the page.
func TestIDPPage_TwoFactor(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Use: []config.Module{twofactor.New(nil)}})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	token, _ := h.Login(t, idp.Handler, "ada@example.com", pagePassword)
	w := h.JSONPost(idp.Handler, "/auth/2fa/setup", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	secret := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["secret"].(string)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.JSONPost(idp.Handler, "/auth/2fa/verify", map[string]interface{}{"code": code}, h.AuthHeader(token)).Code)

	_, challenge := h.PKCEPair(t)
	b := h.NewBrowser(t, idp.Handler)
	page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	requestID := pageRequestID(t, page)

	w = b.Post(h.IDPBase+"/consent/signin", url.Values{"request_id": {requestID}, "email": {"ada@example.com"}, "password": {pagePassword}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Two-factor authentication")
	assert.Empty(t, b.Cookies, "no credentials before the second factor")
	tempToken := hiddenValue(t, w.Body.String(), "temp_token")

	w = b.Post(h.IDPBase+"/consent/2fa", url.Values{"request_id": {requestID}, "temp_token": {tempToken}, "code": {"000000"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "That code is not valid.")
	assert.Empty(t, b.Cookies)

	// The setup code's time step is spent, so use the next one.
	next, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	require.NoError(t, err)
	w = b.Post(h.IDPBase+"/consent/2fa", url.Values{"request_id": {requestID}, "temp_token": {tempToken}, "code": {next}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, page, w.Header().Get("Location"))
	assert.Contains(t, b.Get(page).Body.String(), "Sign in to Test Application")
}

// prompt=login and max_age=0 ask for the password again, and the sign-in
// that follows answers them however long the user takes to approve.
func TestIDPPage_FreshSignIn(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	_, challenge := h.PKCEPair(t)
	b := h.NewBrowser(t, idp.Handler)
	first := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	require.Equal(t, http.StatusSeeOther, pageSignIn(b, pageRequestID(t, first), "ada@example.com", pagePassword).StatusCode)
	// Sign-in times are kept in whole seconds.
	time.Sleep(1100 * time.Millisecond)

	// prompt=consent keeps the question on screen for both, whichever runs
	// first and leaves its approval behind.
	for name, change := range map[string]func(url.Values){
		"prompt=login": func(p url.Values) { p.Set("prompt", "login consent") },
		"max_age=0":    func(p url.Values) { p.Set("max_age", "0"); p.Set("prompt", "consent") },
	} {
		t.Run(name, func(t *testing.T) {
			params := h.IDPAuthorizeParams(challenge)
			change(params)
			page := h.IDPPage(t, b, params)
			requestID := pageRequestID(t, page)
			w := b.Get(page)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			body := w.Body.String()
			assert.Contains(t, body, "asks you to sign in again")
			assert.Contains(t, body, `name="password"`)
			assert.Contains(t, body, `value="ada@example.com"`, "the account is filled in")

			require.Equal(t, http.StatusSeeOther, pageSignIn(b, requestID, "ada@example.com", pagePassword).StatusCode)
			body = b.Get(page).Body.String()
			require.Contains(t, body, "Sign in to Test Application")
			// Reading the question takes longer than a second.
			time.Sleep(1100 * time.Millisecond)
			w = b.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {requestID}, "user": {hiddenValue(t, body, "user")}, "decision": {"approve"}})
			assert.NotEmpty(t, clientRedirect(t, w.Code, w.Header().Get("Location")).Get("code"))
		})
	}
}

// The page's forms act on the browser's cookies, so a form another site
// submits is refused, with or without the CSRF module.
func TestIDPPage_CrossSitePostsAreRefused(t *testing.T) {
	for name, modules := range map[string][]config.Module{"alone": nil, "with the csrf module": {csrf.New(nil)}} {
		t.Run(name, func(t *testing.T) {
			var store types.Storage
			idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Use: modules, Root: func(root *config.Config) { store = root.Storage }})
			// Straight into storage: the signup route is behind the csrf module.
			h.CreateUser(t, store, "ada@example.com", pagePassword, false)
			_, challenge := h.PKCEPair(t)
			b := h.NewBrowser(t, idp.Handler)
			page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
			requestID := pageRequestID(t, page)
			require.Equal(t, http.StatusSeeOther, pageSignIn(b, requestID, "ada@example.com", pagePassword).StatusCode,
				"the page's own forms need no token from the csrf module")
			userID := hiddenValue(t, b.Get(page).Body.String(), "user")
			decision := url.Values{"request_id": {requestID}, "user": {userID}, "decision": {"approve"}}

			b.Site = "cross-site"
			w := b.Post(h.IDPBase+"/consent/decision", decision)
			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), "This request was refused")
			assert.Empty(t, w.Header().Get("Location"))

			// A browser too old to say where a request comes from still
			// names its origin.
			b.Site = ""
			w = b.Post(h.IDPBase+"/consent/decision", decision, map[string]string{"Origin": "https://evil.example"})
			assert.Equal(t, http.StatusForbidden, w.Code)

			b.Site = "same-origin"
			w = b.Post(h.IDPBase+"/consent/decision", decision)
			assert.NotEmpty(t, clientRedirect(t, w.Code, w.Header().Get("Location")).Get("code"), "the request was still open")
		})
	}
}

// A request that is unknown, expired or already answered ends on a page
// that says so, never on a form.
func TestIDPPage_UnknownRequest(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	b := h.NewBrowser(t, idp.Handler)

	for _, path := range []string{h.IDPBase + "/consent", h.IDPBase + "/consent?request_id=nothing"} {
		w := b.Get(path)
		assert.Equal(t, http.StatusNotFound, w.Code, path)
		assert.Contains(t, w.Body.String(), "This sign-in has expired")
		assert.NotContains(t, w.Body.String(), "<form")
	}
	w := b.Post(h.IDPBase+"/consent/signin", url.Values{"request_id": {"nothing"}, "email": {"ada@example.com"}, "password": {pagePassword}})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, b.Cookies, "nobody is signed in for a request that does not exist")
	w = b.Post(h.IDPBase+"/consent/decision", url.Values{"request_id": {"nothing"}, "decision": {"deny"}})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
}

// A request whose client or redirect URI cannot be verified is shown on the
// module's page: a person is looking at it, and must not be sent anywhere.
func TestIDPPage_AuthorizeProblem(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	_, challenge := h.PKCEPair(t)
	params := h.IDPAuthorizeParams(challenge)
	params.Set("redirect_uri", "https://evil.example/callback")

	w := h.IDPAuthorize(idp.Handler, params)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "This application cannot sign you in")
	assert.Contains(t, w.Body.String(), "redirect_uri is not registered for this client")
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "form-action 'self';")
}

// The stylesheet is the page's only other file.
func TestIDPPage_Stylesheet(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true})
	_, challenge := h.PKCEPair(t)
	b := h.NewBrowser(t, idp.Handler)
	body := b.Get(h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))).Body.String()
	marker := `rel="stylesheet" href="`
	start := strings.Index(body, marker) + len(marker)
	href := body[start : start+strings.IndexByte(body[start:], '"')]
	require.True(t, strings.HasPrefix(href, h.IDPBase+"/assets/page.css?v="), href)

	w := b.Get(href)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/css; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Cache-Control"), "immutable")
	assert.Contains(t, w.Body.String(), ".card")
}

// A host with a page of its own gets none of this.
func TestIDPPage_NotServedBesideTheHostsPage(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{})
	b := h.NewBrowser(t, idp.Handler)
	assert.Equal(t, http.StatusNotFound, b.Get(h.IDPBase+"/consent?request_id=nothing").Code)
	assert.Equal(t, http.StatusNotFound, b.Get(h.IDPBase+"/assets/page.css").Code)
	w := b.Post(h.IDPBase+"/consent/signin", url.Values{"request_id": {"nothing"}})
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Header().Get("Content-Type"), "text/html")
}

// SameSite=Strict cookies do not travel with a navigation another site
// started. The page loads itself once more, which is its own navigation.
func TestIDPPage_StrictCookies(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Root: func(root *config.Config) {
		root.Security.Session.SameSite = http.SameSiteStrictMode
	}})
	h.Signup(t, idp.Handler, "ada@example.com", pagePassword, "Ada Lovelace")
	_, challenge := h.PKCEPair(t)

	// What the browser does on arrival: no cookies, a cross-site request.
	arriving := h.NewBrowser(t, idp.Handler)
	arriving.Site = "cross-site"
	page := h.IDPPage(t, arriving, h.IDPAuthorizeParams(challenge))
	w := arriving.Get(page)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	next := page + "&amp;continued=1"
	assert.Contains(t, w.Body.String(), `http-equiv="refresh" content="0;url=`+next+`"`)
	assert.NotContains(t, w.Body.String(), `name="password"`)

	// The page's own navigation carries whatever cookies there are. Without
	// any, it is the sign-in form, and it does not go round again.
	w = arriving.Get(page + "&continued=1")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="password"`)
	assert.NotContains(t, w.Body.String(), "http-equiv")
}

// OAuth connections the host registered are offered on the page, and end
// there again with cookies and no tokens in the address.
func TestIDPPage_SignInWithOAuth(t *testing.T) {
	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Use: []config.Module{oauth.New(&config.OAuthModuleConfig{
		AllowSignup: true, AllowAccountLinking: true, TrustEmailVerification: true,
		Providers: map[string]*config.OAuthProviderConfig{"google": {ClientID: "test-google-client-id", ClientSecret: "secret", Enabled: true}},
	})}})
	_, challenge := h.PKCEPair(t)

	b := h.NewBrowser(t, idp.Handler)
	page := h.IDPPage(t, b, h.IDPAuthorizeParams(challenge))
	body := b.Get(page).Body.String()
	require.Contains(t, body, "Continue with Google")
	start := "/auth/oauth/google?redirect_uri=" + url.QueryEscape(page)
	assert.Contains(t, body, start)

	// The provider round trip: start, then the provider calls back.
	w := b.Get(start)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	authorize, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	fake.Nonce = authorize.Query().Get("nonce")
	fake.ClientID = authorize.Query().Get("client_id")
	w = b.Get("/auth/oauth/google/callback?code=fake_auth_code&state=" + authorize.Query().Get("state"))
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Equal(t, page, w.Header().Get("Location"), "back on the page, with no tokens in the address")
	require.NotEmpty(t, b.Cookies)

	assert.Contains(t, b.Get(page).Body.String(), "Sign in to Test Application")

	// A sign-in the provider could not finish says so on the form.
	w = h.NewBrowser(t, idp.Handler).Get(page + "&error=challenge_required")
	assert.Contains(t, w.Body.String(), "two-factor authentication")
}

// The sign-in form is limited like every other place a password is tried.
func TestIDPPage_SignInIsRateLimited(t *testing.T) {
	idp := h.SetupIDP(t, h.IDPOptions{OwnPage: true, Root: func(root *config.Config) {
		root.RateLimit = &config.RateLimitModuleConfig{Rules: []config.RateLimitRuleConfig{{
			Name: "credential_ip", ApplyTo: []types.RouteName{types.RouteIDPPageSignIn}, Key: types.RateLimitKeyIP, Limit: 2, Window: time.Hour,
		}}}
	}})
	_, challenge := h.PKCEPair(t)
	b := h.NewBrowser(t, idp.Handler)
	requestID := pageRequestID(t, h.IDPPage(t, b, h.IDPAuthorizeParams(challenge)))
	for i := 0; i < 2; i++ {
		assert.Equal(t, http.StatusUnprocessableEntity, pageSignIn(b, requestID, "ada@example.com", "wrong").StatusCode)
	}
	assert.Equal(t, http.StatusTooManyRequests, pageSignIn(b, requestID, "ada@example.com", "wrong").StatusCode)
}
