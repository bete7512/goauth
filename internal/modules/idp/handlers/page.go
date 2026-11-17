package handlers

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/oauth"
	"github.com/bete7512/goauth/internal/modules/saml"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/internal/websession"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// The module's own sign-in and consent page, served when the host names no
// page of its frontend (IDPModuleConfig.ConsentURL is empty). It is plain
// HTML: forms and one stylesheet, no script. The user is whoever the
// application's credential cookies say, signing in goes through the same
// paths as the JSON routes, and the decision goes to the same service
// methods as the consent API.

//go:embed templates/page.html assets/page.css
var pageFS embed.FS

var (
	pageTemplate = template.Must(template.ParseFS(pageFS, "templates/page.html"))
	pageCSS      = mustReadPageFile("assets/page.css")
	// pageCSSVersion lets the stylesheet be cached for good: its address
	// changes whenever its content does.
	pageCSSVersion = func() string {
		sum := sha256.Sum256(pageCSS)
		return hex.EncodeToString(sum[:6])
	}()
)

func mustReadPageFile(name string) []byte {
	body, err := pageFS.ReadFile(name)
	if err != nil {
		panic("idp: " + err.Error())
	}
	return body
}

// Steps of the page.
const (
	stepSignIn    = "signin"
	stepTwoFactor = "twofactor"
	stepConsent   = "consent"
	stepContinue  = "continue"
	stepProblem   = "problem"
)

// maxPageFormBytes bounds a form posted to the page.
const maxPageFormBytes = 16 << 10

// pageLink is a sign-in method that starts somewhere else: an OAuth or
// SAML connection.
type pageLink struct {
	Label, Href string
}

// pageView is what the page template renders.
type pageView struct {
	Title   string
	AppName string
	CSS     string
	// Action is where the page's forms post to, without the last segment.
	Action string
	Step   string

	RequestID    string
	Client       dto.ConsentClient
	Initial      string
	RedirectHost string
	Error        string
	Notice       string

	// Sign-in step.
	Email string
	Links []pageLink
	// Two-factor step.
	TempToken string
	StartOver string
	// Consent step.
	User   *models.User
	Scopes []dto.ConsentScope
	Switch string
	// Problem and continue steps.
	Heading string
	Message string
	Refresh string
}

// pageRoutes are the routes of the module's own page.
func (h *IDPHandler) pageRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{Name: string(types.RouteIDPPage), Path: "/oidc/consent", Method: http.MethodGet, Handler: h.guardPage(h.Page)},
		{Name: string(types.RouteIDPPageSignIn), Path: "/oidc/consent/signin", Method: http.MethodPost, Handler: h.guardPage(h.PageSignIn)},
		{Name: string(types.RouteIDPPageTwoFactor), Path: "/oidc/consent/2fa", Method: http.MethodPost, Handler: h.guardPage(h.PageTwoFactor)},
		{Name: string(types.RouteIDPPageDecision), Path: "/oidc/consent/decision", Method: http.MethodPost, Handler: h.guardPage(h.PageDecision)},
		{Name: string(types.RouteIDPPageAsset), Path: "/oidc/assets/page.css", Method: http.MethodGet, Handler: h.PageAsset},
	}
}

// newPageProtection refuses form posts that another site's page made. The
// issuer and the API address are trusted by name, for a proxy that rewrites
// the Host header.
func newPageProtection(deps config.ModuleDependencies, issuer string, denied http.Handler) *http.CrossOriginProtection {
	protect := http.NewCrossOriginProtection()
	for _, address := range []string{issuer, deps.Config.APIURL} {
		if u, err := url.Parse(address); err == nil && u.Scheme != "" && u.Host != "" {
			if err := protect.AddTrustedOrigin(u.Scheme + "://" + u.Host); err != nil {
				deps.Logger.Warnf("idp: sign-in page: cannot trust origin of %q: %v", address, err)
			}
		}
	}
	protect.SetDenyHandler(denied)
	return protect
}

// guardPage sets the page's security headers and refuses cross-site posts.
func (h *IDPHandler) guardPage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pageHeaders(w, "")
		h.protect.Handler(next).ServeHTTP(w, r)
	}
}

// pageHeaders sets the headers every answer of the page carries. Nothing is
// loaded from another origin, nothing inline runs, and the page cannot be
// framed, so the approving button cannot be clicked through another site.
//
// redirectURI is where the pending request ends. Browsers apply form-action
// to the redirects that follow a form post, so the client's address has to
// be allowed or the browser would stop the user on the way back.
func pageHeaders(w http.ResponseWriter, redirectURI string) {
	formAction := "'self'"
	if source := cspSource(redirectURI); source != "" {
		formAction += " " + source
	}
	header := w.Header()
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src data:; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	// The page's address holds the request ID: it is kept from other sites,
	// and sent to this one, whose cross-origin check may need it.
	header.Set("Referrer-Policy", "same-origin")
	header.Set("Cache-Control", "no-store")
}

var (
	cspSchemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
	cspHostPattern   = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$`)
)

// cspSource turns a redirect URI into a Content-Security-Policy source: the
// origin of a web address, or the scheme of an application's own. It
// returns "" for anything that could not be written into the header safely.
func cspSource(redirectURI string) string {
	if redirectURI == "" {
		return ""
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if !cspSchemePattern.MatchString(scheme) {
		return ""
	}
	if scheme != "http" && scheme != "https" {
		return scheme + ":"
	}
	if !cspHostPattern.MatchString(u.Host) {
		return ""
	}
	return scheme + "://" + u.Host
}

// PageAsset serves the page's stylesheet.
// GET /oidc/assets/page.css
func (h *IDPHandler) PageAsset(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	if r.URL.Query().Get("v") == pageCSSVersion {
		header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		header.Set("Cache-Control", "no-cache")
	}
	header.Set("Content-Type", "text/css; charset=utf-8")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("ETag", `"`+pageCSSVersion+`"`)
	if r.Header.Get("If-None-Match") == `"`+pageCSSVersion+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(pageCSS)
}

// pageURL is the address of the page for a request.
func (h *IDPHandler) pageURL(requestID string, flags ...string) string {
	target := h.settings.PageBase + "/consent?request_id=" + url.QueryEscape(requestID)
	for _, flag := range flags {
		target += "&" + flag + "=1"
	}
	return target
}

// newPageView fills in what every step shows.
func (h *IDPHandler) newPageView(step, title string) *pageView {
	return &pageView{
		Title:   title,
		AppName: h.settings.AppName,
		CSS:     h.settings.PageBase + "/assets/page.css?v=" + pageCSSVersion,
		Action:  h.settings.PageBase + "/consent",
		Step:    step,
	}
}

// renderPage writes a step of the page.
func (h *IDPHandler) renderPage(w http.ResponseWriter, status int, view *pageView) {
	var body bytes.Buffer
	if err := pageTemplate.ExecuteTemplate(&body, "page", view); err != nil {
		h.deps.Logger.Errorf("idp: sign-in page: %v", err)
		http.Error(w, "The page could not be shown.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

// pageProblem shows a dead end: there is nothing to decide any more.
func (h *IDPHandler) pageProblem(w http.ResponseWriter, status int, heading, message string) {
	view := h.newPageView(stepProblem, heading)
	view.Heading, view.Message = heading, message
	h.renderPage(w, status, view)
}

// pageFailure shows why a request cannot go on.
func (h *IDPHandler) pageFailure(w http.ResponseWriter, authErr *types.GoAuthError) {
	switch {
	case authErr.Code == types.ErrIDPRequestNotFound:
		h.pageProblem(w, http.StatusNotFound, "This sign-in has expired",
			"It took too long or was already completed. Go back to the application and sign in again.")
	case authErr.StatusCode >= http.StatusInternalServerError || authErr.StatusCode == 0:
		h.deps.Logger.Errorf("idp: sign-in page: %s: %v", authErr.Message, authErr.Err)
		h.pageProblem(w, http.StatusInternalServerError, "Something went wrong",
			"The sign-in could not be completed. Go back to the application and try again.")
	default:
		h.pageProblem(w, http.StatusForbidden, "This account cannot sign in",
			"Your account cannot be used to sign in to this application.")
	}
}

// loadPage describes the pending request and prepares a view for it. A
// principal without a user describes it to someone who has not signed in.
// It answers the request itself, and returns false, when there is no such
// request any more.
func (h *IDPHandler) loadPage(w http.ResponseWriter, r *http.Request, principal types.Principal, requestID string) (*pageView, *dto.ConsentDetails, bool) {
	details, authErr := h.service.ConsentDetails(r.Context(), principal, requestID)
	if authErr != nil {
		h.pageFailure(w, authErr)
		return nil, nil, false
	}
	redirectURI, authErr := h.service.PendingRedirectURI(r.Context(), requestID)
	if authErr != nil {
		h.pageFailure(w, authErr)
		return nil, nil, false
	}
	pageHeaders(w, redirectURI)

	view := h.newPageView(stepSignIn, "Sign in")
	view.RequestID = requestID
	view.Client = details.Client
	if view.Client.Name == "" {
		view.Client.Name = view.Client.ClientID
	}
	view.Initial = initial(view.Client.Name)
	view.RedirectHost = details.RedirectHost
	view.Scopes = details.Scopes
	return view, details, true
}

// initial is the letter shown in place of an application's logo. The logo
// itself is not loaded: it would tell another server who is about to sign in.
func initial(name string) string {
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return string(unicode.ToUpper(r))
		}
	}
	return "?"
}

// signInLinks lists the OAuth and SAML connections the host registered.
// Each ends at this page again, with the credential cookies set and no
// tokens in the address (http_utils.FinishLocalSignIn).
func (h *IDPHandler) signInLinks(requestID string) []pageLink {
	if h.deps.Lookup == nil {
		return nil
	}
	back := url.QueryEscape(h.pageURL(requestID))
	api := strings.TrimRight(h.deps.Config.BasePath, "/")
	var links []pageLink
	if module, ok := h.deps.Lookup(string(types.OAuthModule)); ok {
		if typed, ok := module.(*oauth.OAuthModule); ok {
			if service := oauth.ServiceOf(typed); service != nil {
				for _, provider := range sortedNames(service.ListEnabledProviders()) {
					links = append(links, pageLink{
						Label: "Continue with " + websession.ProviderLabel(provider),
						Href:  api + "/oauth/" + url.PathEscape(provider) + "?redirect_uri=" + back,
					})
				}
			}
		}
	}
	if module, ok := h.deps.Lookup(string(types.SAMLModule)); ok {
		if typed, ok := module.(*saml.SAMLModule); ok {
			if service := saml.ServiceOf(typed); service != nil {
				for _, provider := range sortedNames(service.ListProviders()) {
					links = append(links, pageLink{
						Label: "Single sign-on: " + websession.ProviderLabel(provider),
						Href:  api + "/saml/" + url.PathEscape(provider) + "/login?redirect_uri=" + back,
					})
				}
			}
		}
	}
	return links
}

func sortedNames(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}

// cookiesWithheld reports whether the browser may have kept the credential
// cookies back: SameSite=Strict cookies do not travel with a navigation
// another site started, which is how every request reaches this page.
func (h *IDPHandler) cookiesWithheld(r *http.Request) bool {
	if h.deps.Config.Security.Session.SameSite != http.SameSiteStrictMode {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
		return false
	}
	return true
}

// Page shows the step the pending request is at: signing in, approving, or
// neither when there is nothing to ask, in which case the browser goes
// straight back to the client.
// GET /oidc/consent?request_id=...
func (h *IDPHandler) Page(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	requestID := query.Get("request_id")
	principal, user, signedIn := h.sessions.Identify(w, r, h.requestMetadata(r))
	if !signedIn {
		principal = types.Principal{}
	}
	view, details, ok := h.loadPage(w, r, principal, requestID)
	if !ok {
		return
	}

	if !signedIn && !query.Has("continued") && h.cookiesWithheld(r) {
		// Load the page once more from the page itself. That navigation is
		// this site's own, so the cookies come with it.
		view.Step, view.Title = stepContinue, "One moment"
		view.Refresh = h.pageURL(requestID, "continued")
		h.renderPage(w, http.StatusOK, view)
		return
	}

	switch {
	case !signedIn:
		view.Email = details.LoginHint
		switch query.Get("error") {
		case "":
		case "challenge_required":
			view.Error = "This account uses two-factor authentication. Sign in with your password to complete it here."
		default:
			view.Error = "That sign-in did not complete. Try again."
		}
	case details.LoginRequired:
		view.Email = user.Email
		view.Notice = view.Client.Name + " asks you to sign in again before you continue."
	case query.Has("switch"):
	case !details.ConsentRequired:
		// Nothing to ask: an application the host runs itself, or one the
		// user approved before.
		target, authErr := h.service.ApproveConsent(r.Context(), principal, requestID, h.requestMetadata(r))
		if authErr != nil {
			h.pageFailure(w, authErr)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	default:
		view.Step, view.Title = stepConsent, "Sign in to "+view.Client.Name
		view.User = user
		view.Switch = h.pageURL(requestID, "switch")
		h.renderPage(w, http.StatusOK, view)
		return
	}
	view.Links = h.signInLinks(requestID)
	h.renderPage(w, http.StatusOK, view)
}

// parsePageForm reads a form posted to the page.
func (h *IDPHandler) parsePageForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPageFormBytes)
	if err := r.ParseForm(); err != nil {
		h.pageProblem(w, http.StatusBadRequest, "The form could not be read", "Go back and try again.")
		return false
	}
	return true
}

// PageSignIn checks a password, the way the login route does, and sets the
// credential cookies.
// POST /oidc/consent/signin
func (h *IDPHandler) PageSignIn(w http.ResponseWriter, r *http.Request) {
	if !h.parsePageForm(w, r) {
		return
	}
	view, _, ok := h.loadPage(w, r, types.Principal{}, r.PostForm.Get("request_id"))
	if !ok {
		return
	}
	view.Links = h.signInLinks(view.RequestID)
	view.Email = strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	if view.Email == "" || password == "" {
		h.signInFailed(w, view, "Enter your email and password.")
		return
	}
	authenticator, ok := h.sessions.Strategy().(types.PasswordAuthenticator)
	if !ok {
		h.signInFailed(w, view, "Password sign-in is unavailable.")
		return
	}
	request := types.SignInRequest{Password: password, Metadata: h.requestMetadata(r)}
	if strings.Contains(view.Email, "@") {
		request.Email = view.Email
	} else {
		request.Username = view.Email
	}
	result, err := authenticator.SignIn(r.Context(), request)
	h.finishPageSignIn(w, r, view, result, err)
}

// PageTwoFactor completes a sign-in that asked for a second step.
// POST /oidc/consent/2fa
func (h *IDPHandler) PageTwoFactor(w http.ResponseWriter, r *http.Request) {
	if !h.parsePageForm(w, r) {
		return
	}
	view, _, ok := h.loadPage(w, r, types.Principal{}, r.PostForm.Get("request_id"))
	if !ok {
		return
	}
	view.Links = h.signInLinks(view.RequestID)
	tempToken := r.PostForm.Get("temp_token")
	code := strings.ReplaceAll(strings.TrimSpace(r.PostForm.Get("code")), " ", "")
	verifier := h.sessions.TwoFactor()
	if verifier == nil || tempToken == "" {
		h.signInFailed(w, view, "This sign-in has expired. Sign in again.")
		return
	}
	if code == "" {
		h.twoFactorStep(w, http.StatusUnprocessableEntity, view, tempToken, "Enter the code from your authenticator app or a backup code.")
		return
	}
	result, err := verifier.VerifyLogin(r.Context(), tempToken, code, h.requestMetadata(r))
	if err != nil {
		var authErr *types.GoAuthError
		if errors.As(err, &authErr) && authErr.Code == types.ErrInvalidToken {
			h.signInFailed(w, view, "This sign-in has expired. Sign in again.")
			return
		}
		h.twoFactorStep(w, http.StatusUnprocessableEntity, view, tempToken, "That code is not valid.")
		return
	}
	h.finishPageSignIn(w, r, view, result, nil)
}

// finishPageSignIn turns the outcome of a sign-in step into the next one:
// a second step, an error, or the page again with the cookies set.
func (h *IDPHandler) finishPageSignIn(w http.ResponseWriter, r *http.Request, view *pageView, result types.AuthenticationResult, err error) {
	if err != nil {
		h.signInFailed(w, view, websession.SignInMessage(err))
		return
	}
	if result.Status == types.ChallengeRequired {
		for _, challenge := range result.Challenges {
			if challenge.Type != types.ChallengeTwoFactor || h.sessions.TwoFactor() == nil {
				continue
			}
			if token, _ := challenge.Data["temp_token"].(string); token != "" {
				h.twoFactorStep(w, http.StatusOK, view, token, "")
				return
			}
		}
		h.signInFailed(w, view, "This account needs a sign-in step this page does not offer.")
		return
	}
	if result.Status != types.Authenticated || result.AccessToken == "" {
		h.signInFailed(w, view, websession.GenericSignInError)
		return
	}
	http_utils.SetCredentialCookies(w, h.deps.Config.Security, result.AccessToken, result.RefreshToken)
	http.Redirect(w, r, h.pageURL(view.RequestID), http.StatusSeeOther)
}

func (h *IDPHandler) signInFailed(w http.ResponseWriter, view *pageView, message string) {
	view.Step, view.Title = stepSignIn, "Sign in"
	view.Error = message
	h.renderPage(w, http.StatusUnprocessableEntity, view)
}

func (h *IDPHandler) twoFactorStep(w http.ResponseWriter, status int, view *pageView, tempToken, message string) {
	view.Step, view.Title = stepTwoFactor, "Two-factor authentication"
	view.TempToken = tempToken
	view.StartOver = h.pageURL(view.RequestID, "switch")
	view.Error = message
	h.renderPage(w, status, view)
}

// PageDecision takes the user's answer and sends the browser back to the
// client: with a code, or with access_denied.
// POST /oidc/consent/decision
func (h *IDPHandler) PageDecision(w http.ResponseWriter, r *http.Request) {
	if !h.parsePageForm(w, r) {
		return
	}
	requestID := r.PostForm.Get("request_id")
	// Before anything else, so that the redirect back to the client is one
	// the page's own policy allows.
	redirectURI, authErr := h.service.PendingRedirectURI(r.Context(), requestID)
	if authErr != nil {
		h.pageFailure(w, authErr)
		return
	}
	pageHeaders(w, redirectURI)
	principal, user, signedIn := h.sessions.Identify(w, r, h.requestMetadata(r))

	var target string
	switch r.PostForm.Get("decision") {
	case "deny":
		// Refusing needs no account: someone who will not sign in may still
		// go back to the application.
		userID := ""
		if signedIn {
			userID = user.ID
		}
		target, authErr = h.service.DenyConsent(r.Context(), userID, requestID, h.requestMetadata(r))
	case "approve":
		// The answer counts for the account the question was put to. Signed
		// out since, or signed in as someone else: ask again.
		if !signedIn || r.PostForm.Get("user") != user.ID {
			http.Redirect(w, r, h.pageURL(requestID), http.StatusSeeOther)
			return
		}
		target, authErr = h.service.ApproveConsent(r.Context(), principal, requestID, h.requestMetadata(r))
		if authErr != nil && authErr.Code == types.ErrIDPLoginRequired {
			http.Redirect(w, r, h.pageURL(requestID), http.StatusSeeOther)
			return
		}
	default:
		h.pageProblem(w, http.StatusBadRequest, "The form could not be read", "Go back and try again.")
		return
	}
	if authErr != nil {
		h.pageFailure(w, authErr)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// authorizeProblem shows, on the module's own page, a request that cannot
// be returned to the client because the client or its redirect URI could
// not be verified.
func (h *IDPHandler) authorizeProblem(w http.ResponseWriter, status int, body dto.OAuthError) {
	pageHeaders(w, "")
	message := "The application that sent you here is not set up correctly. Tell the people who run it."
	if body.ErrorDescription != "" && status < http.StatusInternalServerError {
		message = body.ErrorDescription + ". " + message
	}
	h.pageProblem(w, status, "This application cannot sign you in", message)
}
