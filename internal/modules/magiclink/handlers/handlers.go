package handlers

import (
	"github.com/bete7512/goauth/internal/modules/magiclink/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type MagicLinkHandler struct {
	service services.MagicLinkService
	deps    config.ModuleDependencies
	config  *config.MagicLinkModuleConfig
}

func NewMagicLinkHandler(service services.MagicLinkService, deps config.ModuleDependencies, cfg *config.MagicLinkModuleConfig) *MagicLinkHandler {
	return &MagicLinkHandler{
		service: service,
		deps:    deps,
		config:  cfg,
	}
}

func (h *MagicLinkHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:    string(types.RouteMagicLinkSend),
			Path:    "/magic-link/send",
			Method:  "POST",
			Handler: h.Send,
		},
		{
			Name:    string(types.RouteMagicLinkVerify),
			Path:    "/magic-link/verify",
			Method:  "GET",
			Handler: h.Verify,
		},
		{
			Name:    string(types.RouteMagicLinkVerifyCode),
			Path:    "/magic-link/verify-code",
			Method:  "POST",
			Handler: h.VerifyByCode,
		},
		{
			Name:    string(types.RouteMagicLinkResend),
			Path:    "/magic-link/resend",
			Method:  "POST",
			Handler: h.Resend,
		},
	}
}
