package ui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	coredto "github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/magiclink"
	magicdto "github.com/bete7512/goauth/internal/modules/magiclink/handlers/dto"
	magicservices "github.com/bete7512/goauth/internal/modules/magiclink/services"
	"github.com/bete7512/goauth/internal/modules/oauth"
	passkeydto "github.com/bete7512/goauth/internal/modules/passkeys/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/saml"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/internal/websession"
	"github.com/bete7512/goauth/pkg/types"
)

// Sign-in methods besides the password. Each one goes through its own
// module: OAuth and SAML through their routes, which end at a local path
// with cookies only (http_utils.FinishLocalSignIn); emailed codes and
// passkeys through their services. Every successful method ends in
// finishSignIn, so the administrator check and the two-factor step are the
// same as for a password.

// signInMethods are the buttons the sign-in page shows.
type signInMethods struct {
	OAuth    []signInLink
	SAML     []signInLink
	Code     bool // the magic link module delivers codes
	Passkeys bool
}

type signInLink struct {
	Label, Href string
}

func (s signInMethods) Any() bool {
	return len(s.OAuth) > 0 || len(s.SAML) > 0 || s.Code || s.Passkeys
}

func (m *UIModule) signInMethods(next string) signInMethods {
	var methods signInMethods
	done := m.base + "/login/done"
	if next != "" {
		done += "?next=" + url.QueryEscape(next)
	}
	api := strings.TrimRight(m.deps.Config.BasePath, "/")
	if module, ok := lookup[*oauth.OAuthModule](m, types.OAuthModule); ok {
		if service := oauth.ServiceOf(module); service != nil {
			for _, provider := range sorted(service.ListEnabledProviders()) {
				methods.OAuth = append(methods.OAuth, signInLink{Label: providerLabel(provider), Href: api + "/oauth/" + url.PathEscape(provider) + "?redirect_uri=" + url.QueryEscape(done)})
			}
		}
	}
	if module, ok := lookup[*saml.SAMLModule](m, types.SAMLModule); ok {
		if service := saml.ServiceOf(module); service != nil {
			for _, provider := range sorted(service.ListProviders()) {
				methods.SAML = append(methods.SAML, signInLink{Label: providerLabel(provider), Href: api + "/saml/" + url.PathEscape(provider) + "/login?redirect_uri=" + url.QueryEscape(done)})
			}
		}
	}
	if module, ok := lookup[*magiclink.MagicLinkModule](m, types.MagicLinkModule); ok && magiclink.ServiceOf(module) != nil {
		methods.Code = magiclink.DeliversCodes(module)
	}
	methods.Passkeys = m.passkeyService() != nil
	return methods
}

func sorted(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

// providerLabel names a connection on its button: known providers by
// their brand, anything else as configured.
func providerLabel(name string) string {
	return websession.ProviderLabel(name)
}

// loginDone is where OAuth and SAML sign-ins come back to. The cookies are
// already set; the visitor is checked like any other sign-in.
func (m *UIModule) loginDone(w http.ResponseWriter, r *http.Request) {
	next := m.safeNext(r.URL.Query().Get("next"))
	switch r.URL.Query().Get("error") {
	case "":
	case "challenge_required":
		m.loginFailed(w, r, &loginPage{Next: next}, "This account uses two-factor authentication. Sign in with your password or a passkey to complete it here.")
		return
	default:
		m.loginFailed(w, r, &loginPage{Next: next}, "That sign-in did not complete. Try again.")
		return
	}
	v := m.identify(w, r)
	if v == nil {
		m.loginFailed(w, r, &loginPage{Next: next}, "That sign-in did not complete. Try again.")
		return
	}
	if !v.admin() && !m.config.UserPages {
		if revoker, ok := m.strategy().(types.CredentialRevoker); ok {
			_ = revoker.SignOut(r.Context(), v.Principal)
		}
		http_utils.ClearCredentialCookies(w, m.deps.Config.Security)
		m.loginFailed(w, r, &loginPage{Next: next}, "This console is for administrators.")
		return
	}
	m.redirect(w, r, m.landing(v, next))
}

// --- emailed code (magic link module) ---

func (m *UIModule) magicLink() magicservices.MagicLinkService {
	module, ok := lookup[*magiclink.MagicLinkModule](m, types.MagicLinkModule)
	if !ok || !magiclink.DeliversCodes(module) {
		return nil
	}
	return magiclink.ServiceOf(module)
}

// sendLoginCode emails a sign-in code and asks for it. The answer is the
// same whether or not the address has an account.
func (m *UIModule) sendLoginCode(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	page := &loginPage{Email: strings.TrimSpace(r.PostForm.Get("email")), Next: m.safeNext(r.PostForm.Get("next"))}
	service := m.magicLink()
	if service == nil {
		m.loginFailed(w, r, page, "Sign-in codes are unavailable.")
		return
	}
	request := &magicdto.MagicLinkSendRequest{Email: page.Email}
	if err := request.Validate(); err != nil || !strings.Contains(page.Email, "@") {
		m.loginFailed(w, r, page, "Enter your email address.")
		return
	}
	if _, authErr := service.SendMagicLink(r.Context(), request); authErr != nil && authErr.StatusCode >= http.StatusInternalServerError {
		m.deps.Logger.Error("ui: sign-in code could not be sent", "error", authErr.Error())
		m.loginFailed(w, r, page, "The code could not be sent. Try again.")
		return
	}
	page.CodeSent = true
	m.renderLogin(w, r, http.StatusOK, page, "")
}

func (m *UIModule) verifyLoginCode(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	page := &loginPage{Email: strings.TrimSpace(r.PostForm.Get("email")), Next: m.safeNext(r.PostForm.Get("next")), CodeSent: true}
	service := m.magicLink()
	if service == nil {
		m.loginFailed(w, r, &loginPage{Next: page.Next}, "Sign-in codes are unavailable.")
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(r.PostForm.Get("code")), " ", "")
	if page.Email == "" || code == "" {
		m.loginFailed(w, r, page, "Enter the code from the email.")
		return
	}
	response, authErr := service.VerifyByCode(r.Context(), &magicdto.MagicLinkVerifyByCodeRequest{Email: page.Email, Code: code})
	if authErr != nil {
		message := "That code is not valid."
		if authErr.StatusCode == http.StatusTooManyRequests {
			message = "Too many attempts. Request a new code."
			page.CodeSent = false
		}
		if authErr.Code == types.ErrTokenExpired {
			message = "That code has expired. Request a new one."
			page.CodeSent = false
		}
		m.loginFailed(w, r, page, message)
		return
	}
	m.finishSignIn(w, r, &loginPage{Email: page.Email, Next: page.Next}, authResult(response), nil)
}

// --- passkeys ---

// beginPasskeyLogin starts a WebAuthn sign-in; app.js passes the options to
// the browser.
func (m *UIModule) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	service := m.passkeyService()
	if service == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Passkeys are unavailable."})
		return
	}
	response, authErr := service.BeginLogin(r.Context())
	if authErr != nil {
		m.deps.Logger.Error("ui: passkey sign-in could not start", "error", authErr.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Passkey sign-in could not start."})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// finishPasskeyLogin checks the browser's assertion. It answers JSON with
// the page to go to; the cookies are set on this response.
func (m *UIModule) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	service := m.passkeyService()
	if service == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Passkeys are unavailable."})
		return
	}
	var request passkeydto.FinishLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil || request.ChallengeToken == "" || len(request.CredentialResponse) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "The passkey response could not be read."})
		return
	}
	response, authErr := service.FinishLogin(r.Context(), &request)
	if authErr != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": signInMessage(authErr)})
		return
	}
	next := m.safeNext(r.URL.Query().Get("next"))
	recorder := &passkeyOutcome{header: w.Header()}
	m.finishSignIn(recorder, r, &loginPage{Next: next}, authResult(response), nil)
	switch {
	case recorder.location != "":
		writeJSON(w, http.StatusOK, map[string]string{"redirect": recorder.location})
	default:
		// The outcome was a page (an error, or a step the console shows as a
		// page): have the browser load the sign-in page with that state.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "This account needs another sign-in step. Sign in with your password."})
	}
}

// passkeyOutcome captures finishSignIn's answer so that a fetch request
// gets JSON: the redirect target, with the cookies already on the real
// response's headers.
type passkeyOutcome struct {
	header   http.Header
	location string
	status   int
}

func (o *passkeyOutcome) Header() http.Header { return o.header }
func (o *passkeyOutcome) Write(b []byte) (int, error) {
	return len(b), nil
}
func (o *passkeyOutcome) WriteHeader(status int) {
	o.status = status
	if status == http.StatusSeeOther || status == http.StatusFound {
		o.location = o.header.Get("Location")
	}
	if redirect := o.header.Get("HX-Redirect"); redirect != "" {
		o.location = redirect
	}
	// Nothing of the captured page may reach the client as headers.
	o.header.Del("Location")
	o.header.Del("HX-Redirect")
	o.header.Del("Content-Type")
}

// authResult turns a module's JSON sign-in response into the shape
// finishSignIn takes.
func authResult(response *coredto.AuthResponse) types.AuthenticationResult {
	result := types.AuthenticationResult{Status: types.Denied}
	if response == nil {
		return result
	}
	if len(response.Challenges) > 0 {
		result.Status = types.ChallengeRequired
		result.Challenges = response.Challenges
		return result
	}
	if response.AccessToken != nil && *response.AccessToken != "" {
		result.Status = types.Authenticated
		result.AccessToken = *response.AccessToken
		if response.RefreshToken != nil {
			result.RefreshToken = *response.RefreshToken
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
