package handlers

import (
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type CoreHandler struct {
	coreService core_services.CoreService
	deps        config.ModuleDependencies
}

func NewCoreHandler(coreService core_services.CoreService, deps config.ModuleDependencies) *CoreHandler {
	return &CoreHandler{
		coreService: coreService,
		deps:        deps,
	}
}

func (h *CoreHandler) GetRoutes() []config.RouteInfo {
	routes := []config.RouteInfo{
		// 📌 Core User Management Routes
		// Note: Login/Logout/Refresh are now handled by session or stateless auth modules
		{
			Name:    string(types.RouteSignup),
			Path:    "/signup",
			Method:  "POST",
			Handler: h.Signup,
		},
		{
			Name:        string(types.RouteMe),
			Path:        "/me",
			Method:      "GET",
			Handler:     h.Me,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteUpdateProfile),
			Path:        "/profile",
			Method:      "PUT",
			Handler:     h.UpdateProfile,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteChangePassword),
			Path:        "/change-password",
			Method:      "PUT",
			Handler:     h.ChangePassword,
			Middlewares: []types.MiddlewareName{(types.MiddlewareAuth)},
		},
		{
			Name:    string(types.RouteCheckAvailability),
			Path:    "/is-available",
			Method:  "POST",
			Handler: h.CheckAvailability,
		},

		// Verification Routes
		{
			Name:    string(types.RouteSendVerificationEmail),
			Path:    "/send-verification-email",
			Method:  "POST",
			Handler: h.SendVerificationEmail,
		},
		{
			Name:    string(types.RouteResendVerificationEmail),
			Path:    "/resend-verification-email",
			Method:  "POST",
			Handler: h.ResendVerificationEmail,
		},
		{
			Name:    string(types.RouteSendVerificationPhone),
			Path:    "/send-verification-phone",
			Method:  "POST",
			Handler: h.SendVerificationPhone,
		},
		{
			Name:    string(types.RouteResendVerificationPhone),
			Path:    "/resend-verification-phone",
			Method:  "POST",
			Handler: h.ResendVerificationPhone,
		},
		{
			Name:    string(types.RouteVerifyEmail),
			Path:    "/verify-email",
			Method:  "GET",
			Handler: h.VerifyEmail,
		},
		{
			Name:    string(types.RouteVerifyPhone),
			Path:    "/verify-phone",
			Method:  "POST",
			Handler: h.VerifyPhone,
		},

		// Password Reset Routes
		{
			Name:    string(types.RouteForgotPassword),
			Path:    "/forgot-password",
			Method:  "POST",
			Handler: h.ForgotPassword,
		},
		{
			Name:    string(types.RouteResetPassword),
			Path:    "/reset-password",
			Method:  "POST",
			Handler: h.ResetPassword,
		},
	}
	return routes
}
