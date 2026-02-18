package handlers

import (
	"net/http"

	csrf_services "github.com/bete7512/goauth/internal/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CSRFHandler struct {
	service csrf_services.CSRFService
	config  *config.CSRFModuleConfig
}

func NewCSRFHandler(service csrf_services.CSRFService, cfg *config.CSRFModuleConfig) *CSRFHandler {
	return &CSRFHandler{
		service: service,
		config:  cfg,
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
