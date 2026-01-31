package csrf

import (
	"context"
	"net/http"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/csrf/middlewares"
	"github.com/bete7512/goauth/internal/modules/csrf/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/swagger.yml
var swaggerSpec []byte

// CSRFModule provides CSRF protection using the HMAC-based double-submit cookie pattern.
// Tokens are stateless — no server-side storage is required.
type CSRFModule struct {
	deps    config.ModuleDependencies
	service *services.CSRFService
	config  *config.CSRFModuleConfig
}

var _ config.Module = (*CSRFModule)(nil)

// New creates a new CSRF module with the given configuration.
// If cfg is nil, defaults are used.
func New(cfg *config.CSRFModuleConfig) *CSRFModule {
	if cfg == nil {
		cfg = &config.CSRFModuleConfig{}
	}
	return &CSRFModule{
		config: cfg,
	}
}

func (m *CSRFModule) Name() string {
	return "csrf"
}

func (m *CSRFModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	m.service = services.NewCSRFService(deps.Config.Security.JwtSecretKey, m.config)
	return nil
}

func (m *CSRFModule) Routes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:    "csrf.token",
			Path:    "/csrf-token",
			Method:  "GET",
			Handler: m.handleGetToken,
		},
	}
}

func (m *CSRFModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       "csrf.protect",
			Middleware: middlewares.NewCSRFMiddleware(m.service, m.config),
			Priority:   85,
			Global:     true,
		},
	}
}

func (m *CSRFModule) Models() []interface{} {
	return nil
}

func (m *CSRFModule) RegisterHooks(_ types.EventBus) error {
	return nil
}

func (m *CSRFModule) Dependencies() []string {
	return nil
}

func (m *CSRFModule) SwaggerSpec() []byte {
	return swaggerSpec
}

// handleGetToken generates a CSRF token, sets it as a cookie, and returns it in the response.
// The cookie is NOT HttpOnly so that client-side JavaScript can read it
// and include it in the X-CSRF-Token header on subsequent requests.
func (m *CSRFModule) handleGetToken(w http.ResponseWriter, r *http.Request) {
	token, err := m.service.GenerateToken()
	if err != nil {
		http_utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to generate CSRF token")
		return
	}

	secure := m.config.Secure
	sameSite := m.config.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.service.CookieName(),
		Value:    token,
		Path:     m.service.CookiePath(),
		Domain:   m.service.CookieDomain(),
		MaxAge:   int(m.service.TokenExpiry().Seconds()),
		Secure:   secure,
		HttpOnly: false, // Client JS must read this cookie for double-submit
		SameSite: sameSite,
	})

	http_utils.RespondSuccess(w, map[string]string{"csrf_token": token}, nil)
}
