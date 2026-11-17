// Package websession tells a server-rendered page who is signed in. It reads
// the application's own credential cookies, the way the JSON routes do, and
// exchanges the refresh cookie for new credentials when the access token
// has expired. The ui module's console and the idp module's sign-in page
// both use it, so a browser is signed in to one exactly when it is signed
// in to the other.
package websession

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/bete7512/goauth/internal/security"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// GenericSignInError is what a failed sign-in reads like unless the cause
// is something the user can act on.
const GenericSignInError = "The email or password is incorrect."

// Reader identifies the signed-in user of a browser request.
type Reader struct {
	deps      config.ModuleDependencies
	refreshes refreshGroup
}

// New creates a Reader for one Auth instance.
func New(deps config.ModuleDependencies) *Reader {
	return &Reader{deps: deps}
}

// Strategy returns the module that issues the application's credentials:
// the session module or the stateless one. It is looked up when a request
// needs it, because modules are registered in any order.
func (s *Reader) Strategy() config.Module {
	if s.deps.Lookup == nil {
		return nil
	}
	name := string(types.StatelessModule)
	if s.deps.Config.Security.AuthStrategy == types.StrategySession {
		name = string(types.SessionModule)
	}
	module, _ := s.deps.Lookup(name)
	return module
}

// TwoFactor returns the two-factor module's sign-in step, or nil when the
// module is not registered.
func (s *Reader) TwoFactor() types.TwoFactorLoginVerifier {
	if s.deps.Lookup == nil {
		return nil
	}
	module, ok := s.deps.Lookup(string(types.TwoFactorModule))
	if !ok {
		return nil
	}
	verifier, _ := module.(types.TwoFactorLoginVerifier)
	return verifier
}

// Identify returns the signed-in user, refreshing the credentials when the
// access token has expired and a refresh token is still valid; the new
// cookies are set on w. ok is false when nobody is signed in.
func (s *Reader) Identify(w http.ResponseWriter, r *http.Request, metadata *types.RequestMetadata) (principal types.Principal, user *models.User, ok bool) {
	cfg := s.deps.Config
	principal, err := security.ValidateAccess(r.Context(), cfg, s.deps.SecurityManager, http_utils.AccessCredential(r, cfg.Security))
	if err != nil {
		principal, err = s.refresh(w, r, metadata)
	}
	if err != nil {
		return types.Principal{}, nil, false
	}
	user, err = s.deps.Storage.Core().Users().FindByID(r.Context(), principal.UserID)
	if err != nil || user == nil || !user.Active {
		return types.Principal{}, nil, false
	}
	return principal, user, true
}

// refresh exchanges the refresh cookie for new credentials. Only cookies
// are read: a page never takes credentials from a header or form.
func (s *Reader) refresh(w http.ResponseWriter, r *http.Request, metadata *types.RequestMetadata) (types.Principal, error) {
	cookie, err := r.Cookie("goauth_refresh_" + s.deps.Config.Security.Session.Name)
	if err != nil || cookie.Value == "" {
		return types.Principal{}, errors.New("no refresh credential")
	}
	refresher, ok := s.Strategy().(types.CredentialRefresher)
	if !ok {
		return types.Principal{}, errors.New("refresh unavailable")
	}
	// Requests that arrive together with the same expired access token share
	// one refresh: rotation accepts a refresh token once, so separate
	// refreshes would fail every request but the first.
	result, err := s.refreshes.do(cookie.Value, func() (types.AuthenticationResult, error) {
		return refresher.RefreshCredentials(context.WithoutCancel(r.Context()), cookie.Value, metadata)
	})
	if err != nil || result.Status != types.Authenticated || result.AccessToken == "" {
		return types.Principal{}, errors.New("refresh refused")
	}
	principal, err := security.ValidateAccess(r.Context(), s.deps.Config, s.deps.SecurityManager, result.AccessToken)
	if err != nil {
		return types.Principal{}, err
	}
	http_utils.SetCredentialCookies(w, s.deps.Config.Security, result.AccessToken, result.RefreshToken)
	return principal, nil
}

// CookieReaches reports whether a cookie scoped to cookiePath is sent with
// requests to mount.
func CookieReaches(cookiePath, mount string) bool {
	if cookiePath == "" || cookiePath == "/" {
		return true
	}
	cookiePath = strings.TrimRight(cookiePath, "/")
	return mount == cookiePath || strings.HasPrefix(mount, cookiePath+"/")
}

// ProviderLabel names an OAuth or SAML connection on its sign-in button:
// known providers by their brand, anything else as configured.
func ProviderLabel(name string) string {
	known := map[string]string{"google": "Google", "github": "GitHub", "microsoft": "Microsoft", "discord": "Discord", "apple": "Apple", "gitlab": "GitLab", "okta": "Okta"}
	if label, ok := known[strings.ToLower(name)]; ok {
		return label
	}
	return name
}

// SignInMessage keeps the answer to a failed sign-in as uninformative as
// the API's: a locked or unknown account reads like a wrong password.
func SignInMessage(err error) string {
	var authErr *types.GoAuthError
	if !errors.As(err, &authErr) {
		return GenericSignInError
	}
	switch authErr.Code {
	case types.ErrEmailNotVerified:
		return "Verify your email address before signing in."
	case types.ErrAccountLocked:
		return "This account is temporarily locked. Try again later."
	case types.ErrUserNotActive, types.ErrAccountDeactivated, types.ErrUserBlocked:
		return "This account cannot sign in."
	default:
		return GenericSignInError
	}
}

// refreshGroup runs one refresh per refresh token at a time; callers that
// arrive while it runs wait for it and share its result. Nothing is kept
// once it finishes, so a token is never exchanged from memory later.
type refreshGroup struct {
	mu       sync.Mutex
	inFlight map[[32]byte]*refreshCall
}

type refreshCall struct {
	done   chan struct{}
	result types.AuthenticationResult
	err    error
}

func (g *refreshGroup) do(token string, refresh func() (types.AuthenticationResult, error)) (types.AuthenticationResult, error) {
	key := sha256.Sum256([]byte(token))
	g.mu.Lock()
	if g.inFlight == nil {
		g.inFlight = map[[32]byte]*refreshCall{}
	}
	if call, ok := g.inFlight[key]; ok {
		g.mu.Unlock()
		<-call.done
		return call.result, call.err
	}
	call := &refreshCall{done: make(chan struct{})}
	g.inFlight[key] = call
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.inFlight, key)
		g.mu.Unlock()
		close(call.done)
	}()
	call.result, call.err = refresh()
	return call.result, call.err
}
