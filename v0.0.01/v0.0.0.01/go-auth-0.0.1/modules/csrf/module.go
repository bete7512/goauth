package csrf

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/modules/csrf/middlewares"
	"github.com/bete7512/goauth/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CSRFModule struct {
	deps    config.ModuleDependencies
	service *services.CSRFService
	config  *CSRFConfig
}

type CSRFConfig struct {
	// Token settings
	TokenLength   int
	TokenExpiry   int // in seconds
	CookieName    string
	HeaderName    string
	FormFieldName string

	// Cookie settings
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite

	// Paths to exclude from CSRF protection
	ExcludePaths []string

	// Methods that require CSRF protection
	ProtectedMethods []string
}

var _ config.Module = (*CSRFModule)(nil)

func New(cfg ...*CSRFConfig) *CSRFModule {
	var moduleConfig *CSRFConfig
	if len(cfg) > 0 && cfg[0] != nil {
		moduleConfig = cfg[0]
	} else {
		moduleConfig = &CSRFConfig{
			TokenLength:      32,
			TokenExpiry:      3600, // 1 hour
			CookieName:       "csrf_token",
			HeaderName:       "X-CSRF-Token",
			FormFieldName:    "csrf_token",
			Secure:           true,
			HTTPOnly:         true,
			SameSite:         http.SameSiteStrictMode,
			ExcludePaths:     []string{},
			ProtectedMethods: []string{"POST", "PUT", "DELETE", "PATCH"},
		}
	}

	return &CSRFModule{
		config: moduleConfig,
	}
}

func (m *CSRFModule) Name() string {
	return "csrf"
}

func (m *CSRFModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Initialize CSRF service
	m.service = services.NewCSRFService(
		m.config.TokenLength,
		m.config.TokenExpiry,
		m.config.CookieName,
		m.config.HeaderName,
		m.config.FormFieldName,
	)

	return nil
}

func (m *CSRFModule) Routes() []config.RouteInfo {
	// Provide an endpoint to get CSRF token
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
			Global:     true, // Apply to all routes
		},
	}
}

func (m *CSRFModule) Models() []interface{} {
	return nil // No models needed (uses in-memory or session storage)
}

func (m *CSRFModule) RegisterHooks(events config.EventBus) error {
	return nil
}

func (m *CSRFModule) Dependencies() []string {
	return nil
}

// handleGetToken returns a CSRF token
func (m *CSRFModule) handleGetToken(w http.ResponseWriter, r *http.Request) {
	token, err := m.service.GenerateToken()
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   m.config.TokenExpiry,
		Secure:   m.config.Secure,
		HttpOnly: m.config.HTTPOnly,
		SameSite: m.config.SameSite,
	}
	http.SetCookie(w, cookie)

	// Return token in response
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"csrf_token":"` + token + `"}`))
}
