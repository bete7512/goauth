package handlers

import (
	"net/http"

	csrf_services "github.com/bete7512/goauth/internal/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CSRFHandler struct {
	service csrf_services.CSRFService
	config  *config.CSRFModuleConfig
	// allowInsecureCookies mirrors Security.Session.AllowInsecureCookies.
	allowInsecureCookies bool
}

// NewCSRFHandler creates the handler. allowInsecureCookies comes from the root
// Security.Session setting; the CSRF cookie is Secure unless it is true.
func NewCSRFHandler(service csrf_services.CSRFService, cfg *config.CSRFModuleConfig, allowInsecureCookies bool) *CSRFHandler {
	return &CSRFHandler{
		service:              service,
		config:               cfg,
		allowInsecureCookies: allowInsecureCookies,
	}
}

func (h *CSRFHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:    "csrf.token",
			Path:    "/csrf-token",
			Method:  http.MethodGet,
			Handler: h.GetToken,
		},
	}
}
