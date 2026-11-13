// Package handlers exposes the SAML module over HTTP.
package handlers

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/saml/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

const bindingCookiePrefix = "goauth_saml_"

// SAMLHandler handles SAML HTTP requests.
type SAMLHandler struct {
	service services.SAMLService
	deps    config.ModuleDependencies
	config  *config.SAMLModuleConfig
}

// NewSAMLHandler creates the handler.
func NewSAMLHandler(service services.SAMLService, deps config.ModuleDependencies, cfg *config.SAMLModuleConfig) *SAMLHandler {
	return &SAMLHandler{service: service, deps: deps, config: cfg}
}

// GetRoutes returns the module routes.
func (h *SAMLHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{Name: string(types.RouteSAMLProviders), Path: "/saml/providers", Method: http.MethodGet, Handler: h.ListProviders},
		{Name: string(types.RouteSAMLLogin), Path: "/saml/{provider}/login", Method: http.MethodGet, Handler: h.Login},
		{Name: string(types.RouteSAMLACS), Path: "/saml/{provider}/acs", Method: http.MethodPost, Handler: h.ACS},
		{Name: string(types.RouteSAMLMetadata), Path: "/saml/{provider}/metadata", Method: http.MethodGet, Handler: h.Metadata},
	}
}

// providerFromPath extracts the connection name from /saml/{provider}/... paths.
func providerFromPath(r *http.Request) string {
	path := r.URL.Path
	idx := strings.Index(path, "/saml/")
	if idx == -1 {
		return ""
	}
	rest := strings.SplitN(path[idx+len("/saml/"):], "/", 2)
	if len(rest) < 2 || rest[0] == "" || rest[0] == "providers" {
		return ""
	}
	return rest[0]
}

// bindingCookie binds the browser that started a login to the response the
// IdP posts back. The ACS is a cross-site POST, so a Lax cookie would not be
// sent: use SameSite=None with Secure, and omit the attribute on plain HTTP
// development setups so the browser's Lax-by-default POST exception applies.
func (h *SAMLHandler) bindingCookie(provider, value string, maxAge int) *http.Cookie {
	secure := h.deps.Config.Security.Session.Secure
	cookie := &http.Cookie{
		Name:     bindingCookiePrefix + provider,
		Value:    value,
		Path:     h.deps.Config.BasePath + "/saml/" + provider + "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   maxAge,
	}
	if secure {
		cookie.SameSite = http.SameSiteNoneMode
	}
	return cookie
}
