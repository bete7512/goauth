//go:build integration

package testhelpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/csrf"
	"github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/bete7512/goauth/pkg/modules/invitation"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/passkeys"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/modules/ui"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// UIOptions selects what a console test instance has besides the ui module.
type UIOptions struct {
	UI            *ui.Config
	Audit         bool
	RBAC          *rbac.Config
	TwoFactor     bool
	CSRF          bool
	RateLimit     *config.RateLimitModuleConfig
	Session       bool
	Organizations bool
	Invitations   bool
	IDP           bool
	OAuth         bool
	Passkeys      bool
	AuthMode      types.AuthMode
	Mutate        func(*config.Config)
}

// UIEnv is a running instance with the console.
type UIEnv struct {
	Auth    *auth.Auth
	Handler http.Handler
	Store   types.Storage
}

// SetupUI creates an instance with the ui module and the modules opts asks for.
func SetupUI(t *testing.T, opts UIOptions) *UIEnv {
	t.Helper()
	store := newStore(t)
	security := defaultSecurityConfig("ui-test-secret-key-32-characters", "ui-test-encryption-key-32-chars!")
	security.AuthMode = opts.AuthMode
	rateLimit := opts.RateLimit
	if rateLimit == nil {
		rateLimit = &config.RateLimitModuleConfig{Disabled: true}
	}
	cfg := &config.Config{
		APIURL:    "http://localhost:8080",
		Storage:   store,
		BasePath:  "/auth",
		Security:  security,
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		RateLimit: rateLimit,
		Migration: config.MigrationConfig{Auto: true},
	}
	if opts.Mutate != nil {
		opts.Mutate(cfg)
	}
	authInstance, err := auth.New(cfg)
	require.NoError(t, err)
	require.NoError(t, authInstance.Use(ui.New(opts.UI)))
	require.NoError(t, authInstance.Use(admin.New(nil)))
	if opts.Audit {
		require.NoError(t, authInstance.Use(audit.New(nil)))
	}
	if opts.RBAC != nil {
		require.NoError(t, authInstance.Use(rbac.New(opts.RBAC)))
	}
	if opts.TwoFactor {
		require.NoError(t, authInstance.Use(twofactor.New(nil)))
	}
	if opts.CSRF {
		require.NoError(t, authInstance.Use(csrf.New(nil)))
	}
	if opts.Session {
		require.NoError(t, authInstance.Use(sessionModule()))
	}
	if opts.Organizations {
		require.NoError(t, authInstance.Use(organization.New(nil)))
	}
	if opts.Invitations {
		require.NoError(t, authInstance.Use(invitation.New(nil)))
	}
	if opts.OAuth {
		require.NoError(t, authInstance.Use(oauth.New(nil)))
	}
	if opts.Passkeys {
		require.NoError(t, authInstance.Use(passkeys.New(&config.PasskeysModuleConfig{RPID: "localhost", RPOrigins: []string{"http://localhost:3000"}})))
	}
	if opts.IDP {
		require.NoError(t, authInstance.Use(idp.New(&config.IDPModuleConfig{
			SigningKey: config.IDPSigningKey{PrivateKeyPEM: RSAKeyPEM(t)},
			ConsentURL: "http://localhost:3000/consent",
		})))
	}
	if err := authInstance.Initialize(context.Background()); err != nil {
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, authInstance.Close()) })
	mux := http.NewServeMux()
	return &UIEnv{Auth: authInstance, Handler: stdhttp.Register(mux, authInstance), Store: store}
}

// Browser keeps cookies between requests and sends the headers a browser
// sends for a same-origin page.
type Browser struct {
	t       *testing.T
	handler http.Handler
	Cookies map[string]*http.Cookie
	// Site is the Sec-Fetch-Site value sent with every request.
	Site string
}

// NewBrowser starts a browser with no cookies.
func NewBrowser(t *testing.T, handler http.Handler) *Browser {
	return &Browser{t: t, handler: handler, Cookies: map[string]*http.Cookie{}, Site: "same-origin"}
}

// Get loads a page.
func (b *Browser) Get(path string, headers ...map[string]string) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, path, nil, headers...)
}

// Post submits a form.
func (b *Browser) Post(path string, form url.Values, headers ...map[string]string) *httptest.ResponseRecorder {
	return b.do(http.MethodPost, path, form, headers...)
}

func (b *Browser) do(method, path string, form url.Values, headers ...map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Accept", "text/html")
	if b.Site != "" {
		req.Header.Set("Sec-Fetch-Site", b.Site)
	}
	for _, cookie := range b.Cookies {
		req.AddCookie(cookie)
	}
	for _, set := range headers {
		for key, value := range set {
			req.Header.Set(key, value)
		}
	}
	rec := httptest.NewRecorder()
	b.handler.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(b.Cookies, cookie.Name)
			continue
		}
		b.Cookies[cookie.Name] = cookie
	}
	return rec
}

// SignIn submits the console's sign-in form and returns the response.
func (b *Browser) SignIn(email, password string) *httptest.ResponseRecorder {
	return b.Post("/auth/ui/login", url.Values{"email": {email}, "password": {password}})
}

func sessionModule() config.Component {
	return session.New(&config.SessionModuleConfig{EnableSessionManagement: true})
}

// NewStore returns an isolated in-memory store.
func NewStore(t *testing.T) types.Storage { return newStore(t) }

// CreateUser stores a user with a password directly, skipping the signup
// route, and returns the user's ID.
func CreateUser(t *testing.T, store types.Storage, email, password string, superAdmin bool) string {
	t.Helper()
	user := &models.User{ID: uuid.NewString(), Email: email, Username: email, Name: "Test User", PasswordHash: testutil.HashPassword(password), Active: true, EmailVerified: true, IsSuperAdmin: superAdmin}
	require.NoError(t, store.Core().Users().Create(context.Background(), user))
	return user.ID
}
