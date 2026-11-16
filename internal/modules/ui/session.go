package ui

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bete7512/goauth/internal/security"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// contentSecurityPolicy allows scripts, styles and requests from the
// console's own origin only. htmx is configured (in the layout) not to
// inject styles or evaluate code, so nothing inline is needed.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// secure adds the headers every console response carries.
func (m *UIModule) secure(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Add("Vary", "HX-Request")
		next(w, r)
	}
}

// visitor is the signed-in user of a request.
type visitor struct {
	Principal types.Principal
	User      *models.User
}

func (v *visitor) admin() bool { return v != nil && v.User != nil && v.User.IsSuperAdmin }

type visitorKey struct{}

func visitorFrom(ctx context.Context) *visitor {
	v, _ := ctx.Value(visitorKey{}).(*visitor)
	return v
}

// identify returns the signed-in user, refreshing the credentials when the
// access token has expired and a refresh token is still valid. It returns
// nil when nobody is signed in.
func (m *UIModule) identify(w http.ResponseWriter, r *http.Request) *visitor {
	cfg := m.deps.Config
	principal, err := security.ValidateAccess(r.Context(), cfg, m.deps.SecurityManager, http_utils.AccessCredential(r, cfg.Security))
	if err != nil {
		principal, err = m.refresh(w, r)
	}
	if err != nil {
		return nil
	}
	user, err := m.deps.Storage.Core().Users().FindByID(r.Context(), principal.UserID)
	if err != nil || user == nil || !user.Active {
		return nil
	}
	return &visitor{Principal: principal, User: user}
}

// refresh exchanges the refresh cookie for new credentials. Only cookies
// are read: the console never takes credentials from a header or form.
func (m *UIModule) refresh(w http.ResponseWriter, r *http.Request) (types.Principal, error) {
	cookie, err := r.Cookie("goauth_refresh_" + m.deps.Config.Security.Session.Name)
	if err != nil || cookie.Value == "" {
		return types.Principal{}, errors.New("no refresh credential")
	}
	refresher, ok := m.strategy().(types.CredentialRefresher)
	if !ok {
		return types.Principal{}, errors.New("refresh unavailable")
	}
	// Requests that arrive together with the same expired access token share
	// one refresh: rotation accepts a refresh token once, so separate
	// refreshes would fail every request but the first.
	result, err := m.refreshes.do(cookie.Value, func() (types.AuthenticationResult, error) {
		return refresher.RefreshCredentials(context.WithoutCancel(r.Context()), cookie.Value, metadata(r))
	})
	if err != nil || result.Status != types.Authenticated || result.AccessToken == "" {
		return types.Principal{}, errors.New("refresh refused")
	}
	principal, err := security.ValidateAccess(r.Context(), m.deps.Config, m.deps.SecurityManager, result.AccessToken)
	if err != nil {
		return types.Principal{}, err
	}
	http_utils.SetCredentialCookies(w, m.deps.Config.Security, result.AccessToken, result.RefreshToken)
	return principal, nil
}

// withVisitor puts the visitor where GoAuth's services look for the caller.
func withVisitor(r *http.Request, v *visitor) *http.Request {
	ctx := types.WithPrincipal(r.Context(), v.Principal)
	ctx = context.WithValue(ctx, types.UserIDKey, v.Principal.UserID)
	ctx = context.WithValue(ctx, types.UserKey, v.User)
	if v.Principal.SessionID != "" {
		ctx = context.WithValue(ctx, types.SessionIDKey, v.Principal.SessionID)
	}
	ctx = context.WithValue(ctx, visitorKey{}, v)
	return r.WithContext(ctx)
}

// signedIn serves next to any signed-in user and sends everyone else to the
// sign-in page.
func (m *UIModule) signedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := m.identify(w, r)
		if v == nil {
			m.toLogin(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next(w, withVisitor(r, v))
	}
}

// adminOnly serves next to super admins only.
func (m *UIModule) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return m.signedIn(func(w http.ResponseWriter, r *http.Request) {
		if !visitorFrom(r.Context()).admin() {
			if !m.config.UserPages {
				// Only administrators use this console: let them sign in.
				m.toLogin(w, r)
				return
			}
			m.renderError(w, r, http.StatusForbidden, "This page is for administrators.")
			return
		}
		next(w, r)
	})
}

// toLogin sends the browser to the sign-in page and back here afterwards.
func (m *UIModule) toLogin(w http.ResponseWriter, r *http.Request) {
	target := m.base + "/login"
	if r.Method == http.MethodGet {
		target += "?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	m.redirect(w, r, target)
}

// redirect answers with a 303, or, for an htmx request, asks htmx to load
// the page itself so that it does not swap a whole page into a fragment.
func (m *UIModule) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Boosted") != "true" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// safeNext accepts only paths inside the console, so the sign-in page cannot
// be used to send someone to another site.
func (m *UIModule) safeNext(next string) string {
	if next == "" || (next != m.base && !strings.HasPrefix(next, m.base+"/")) {
		return ""
	}
	if strings.Contains(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return ""
	}
	parsed, err := url.Parse(next)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return ""
	}
	// A browser resolves dot segments, so "/auth/ui/../../x" would leave the
	// console. Accept only a path that is already in its clean form.
	if cleaned := path.Clean(parsed.Path); cleaned != parsed.Path ||
		(cleaned != m.base && !strings.HasPrefix(cleaned, m.base+"/")) ||
		strings.HasPrefix(cleaned, m.base+"/login") {
		return ""
	}
	return next
}

func metadata(r *http.Request) *types.RequestMetadata {
	return &types.RequestMetadata{IPAddress: r.RemoteAddr, UserAgent: r.UserAgent(), Timestamp: time.Now()}
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
