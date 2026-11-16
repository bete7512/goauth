package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/security"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

const genericSignInError = "The email or password is incorrect."

type loginPage struct {
	Email     string
	Next      string
	TempToken string // set on the second step of a two-factor sign-in
	// CodeSent is set on the step that asks for an emailed sign-in code.
	CodeSent bool
	Methods  signInMethods
}

// home sends visitors where they belong: administrators to the console,
// others to their account page, everyone else to sign in.
func (m *UIModule) home(w http.ResponseWriter, r *http.Request) {
	v := m.identify(w, r)
	switch {
	case v == nil:
		m.redirect(w, r, m.base+"/login")
	case v.admin():
		w.Header().Set("Cache-Control", "no-store")
		m.dashboard(w, withVisitor(r, v))
	case m.config.UserPages:
		m.redirect(w, r, m.base+"/account")
	default:
		m.renderError(w, withVisitor(r, v), http.StatusForbidden, "This console is for administrators.")
	}
}

func (m *UIModule) loginPage(w http.ResponseWriter, r *http.Request) {
	if v := m.identify(w, r); v != nil && (v.admin() || m.config.UserPages) {
		m.redirect(w, r, m.landing(v, m.safeNext(r.URL.Query().Get("next"))))
		return
	}
	page := &loginPage{Next: m.safeNext(r.URL.Query().Get("next"))}
	m.renderLogin(w, r, http.StatusOK, page, "")
}

// renderLogin shows a step of the sign-in page with the sign-in methods the
// registered modules offer.
func (m *UIModule) renderLogin(w http.ResponseWriter, r *http.Request, status int, page *loginPage, message string) {
	title := "Sign in"
	if page.TempToken != "" {
		title = "Two-factor authentication"
	}
	page.Methods = m.signInMethods(page.Next)
	data := m.newView(r, title, "", page)
	data.Error = message
	m.render(w, r, status, "login", data)
}

func (m *UIModule) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		m.loginFailed(w, r, &loginPage{}, "The form could not be read.")
		return
	}
	page := &loginPage{Email: strings.TrimSpace(r.PostForm.Get("email")), Next: m.safeNext(r.PostForm.Get("next"))}
	password := r.PostForm.Get("password")
	if page.Email == "" || password == "" {
		m.loginFailed(w, r, page, "Enter your email and password.")
		return
	}
	authenticator, ok := m.strategy().(types.PasswordAuthenticator)
	if !ok {
		m.loginFailed(w, r, page, "Password sign-in is unavailable.")
		return
	}
	request := types.SignInRequest{Password: password, Metadata: metadata(r)}
	if strings.Contains(page.Email, "@") {
		request.Email = page.Email
	} else {
		request.Username = page.Email
	}
	result, err := authenticator.SignIn(r.Context(), request)
	m.finishSignIn(w, r, page, result, err)
}

func (m *UIModule) loginTwoFactor(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		m.loginFailed(w, r, &loginPage{}, "The form could not be read.")
		return
	}
	page := &loginPage{Next: m.safeNext(r.PostForm.Get("next")), TempToken: r.PostForm.Get("temp_token")}
	code := strings.ReplaceAll(strings.TrimSpace(r.PostForm.Get("code")), " ", "")
	verifier := m.twoFactor()
	if verifier == nil || page.TempToken == "" {
		m.loginFailed(w, r, &loginPage{Next: page.Next}, "This sign-in has expired. Sign in again.")
		return
	}
	if code == "" {
		m.loginFailed(w, r, page, "Enter the code from your authenticator app or a backup code.")
		return
	}
	result, err := verifier.VerifyLogin(r.Context(), page.TempToken, code, metadata(r))
	if err != nil {
		var authErr *types.GoAuthError
		if errors.As(err, &authErr) && authErr.Code == types.ErrInvalidToken {
			m.loginFailed(w, r, &loginPage{Next: page.Next}, "This sign-in has expired. Sign in again.")
			return
		}
		m.loginFailed(w, r, page, "That code is not valid.")
		return
	}
	m.finishSignIn(w, r, page, result, nil)
}

// finishSignIn turns the outcome of a sign-in step into a page: a second
// step, an error, or the destination with fresh cookies.
func (m *UIModule) finishSignIn(w http.ResponseWriter, r *http.Request, page *loginPage, result types.AuthenticationResult, err error) {
	if err != nil {
		m.loginFailed(w, r, page, signInMessage(err))
		return
	}
	if result.Status == types.ChallengeRequired {
		for _, challenge := range result.Challenges {
			if challenge.Type != types.ChallengeTwoFactor || m.twoFactor() == nil {
				continue
			}
			token, _ := challenge.Data["temp_token"].(string)
			if token == "" {
				break
			}
			m.renderLogin(w, r, http.StatusOK, &loginPage{Next: page.Next, TempToken: token}, "")
			return
		}
		m.loginFailed(w, r, &loginPage{Email: page.Email, Next: page.Next}, "This account needs a sign-in step the console does not support. Sign in through your application.")
		return
	}
	if result.Status != types.Authenticated || result.AccessToken == "" {
		m.loginFailed(w, r, page, genericSignInError)
		return
	}
	principal, err := security.ValidateAccess(r.Context(), m.deps.Config, m.deps.SecurityManager, result.AccessToken)
	if err != nil {
		m.loginFailed(w, r, page, genericSignInError)
		return
	}
	user, err := m.deps.Storage.Core().Users().FindByID(r.Context(), principal.UserID)
	if err != nil || user == nil {
		m.loginFailed(w, r, page, genericSignInError)
		return
	}
	v := &visitor{Principal: principal, User: user}
	if !v.admin() && !m.config.UserPages {
		// The credentials were issued before the account could be checked;
		// take them back rather than leave a session nobody asked for.
		if revoker, ok := m.strategy().(types.CredentialRevoker); ok {
			_ = revoker.SignOut(r.Context(), principal)
		}
		m.loginFailed(w, r, &loginPage{Email: page.Email, Next: page.Next}, "This console is for administrators.")
		return
	}
	http_utils.SetCredentialCookies(w, m.deps.Config.Security, result.AccessToken, result.RefreshToken)
	m.redirect(w, r, m.landing(v, page.Next))
}

// landing is where a signed-in visitor goes: next when it is a page they
// may open, otherwise their home page. Administrators may open any console
// page; everyone else only their account page.
func (m *UIModule) landing(v *visitor, next string) string {
	account := m.base + "/account"
	switch {
	case v.admin() && next != "":
		return next
	case v.admin():
		return m.base
	case next == account || strings.HasPrefix(next, account+"?"):
		return next
	default:
		return account
	}
}

func (m *UIModule) loginFailed(w http.ResponseWriter, r *http.Request, page *loginPage, message string) {
	m.renderLogin(w, r, http.StatusUnprocessableEntity, page, message)
}

// signInMessage keeps the answer to a failed sign-in as uninformative as
// the API's: a locked or unknown account reads like a wrong password.
func signInMessage(err error) string {
	var authErr *types.GoAuthError
	if !errors.As(err, &authErr) {
		return genericSignInError
	}
	switch authErr.Code {
	case types.ErrEmailNotVerified:
		return "Verify your email address before signing in."
	case types.ErrAccountLocked:
		return "This account is temporarily locked. Try again later."
	case types.ErrUserNotActive, types.ErrAccountDeactivated, types.ErrUserBlocked:
		return "This account cannot sign in."
	default:
		return genericSignInError
	}
}

func (m *UIModule) logout(w http.ResponseWriter, r *http.Request) {
	cfg := m.deps.Config
	if principal, err := security.ValidateAccess(r.Context(), cfg, m.deps.SecurityManager, http_utils.AccessCredential(r, cfg.Security)); err == nil {
		if revoker, ok := m.strategy().(types.CredentialRevoker); ok {
			if err := revoker.SignOut(r.Context(), principal); err != nil {
				m.deps.Logger.Warn("ui: sign-out could not revoke credentials", "error", err)
			}
		}
	}
	http_utils.ClearCredentialCookies(w, cfg.Security)
	m.redirect(w, r, m.base+"/login?notice=signed-out")
}
