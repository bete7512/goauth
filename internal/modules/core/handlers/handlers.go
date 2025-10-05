package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreHandler struct {
	deps        config.ModuleDependencies
	CoreService *core_services.CoreService
}

func NewCoreHandler(deps config.ModuleDependencies, coreService *core_services.CoreService) *CoreHandler {
	return &CoreHandler{
		deps:        deps,
		CoreService: coreService,
	}
}

func (h *CoreHandler) GetRoutes() []config.RouteInfo {
	// register routes here with unique names
	authMiddleware := middlewares.NewAuthMiddleware(h.deps.Config, h.CoreService.SecurityManager)
	routes := []config.RouteInfo{
		// 📌 Core Auth Routes
		{
			Name:    "core.signup",
			Path:    "/signup",
			Method:  "POST",
			Handler: h.Signup,
		},
		{
			Name:    "core.login",
			Path:    "/login",
			Method:  "POST",
			Handler: h.Login,
		},
		{
			Name:    "core.logout",
			Path:    "/logout",
			Method:  "POST",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.Logout)).ServeHTTP,
		},
		{
			Name:    "core.me",
			Path:    "/me",
			Method:  "GET",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.Me)).ServeHTTP,
		},

		// 📌 Email / Phone Verification
		{
			Name:    "core.send_verification_email",
			Path:    "/send-verification-email",
			Method:  "POST",
			Handler: h.SendVerificationEmail,
		},
		{
			Name:    "core.verify_email",
			Path:    "/verify-email",
			Method:  "POST",
			Handler: h.VerifyEmail,
		},
		{
			Name:    "core.send_verification_phone",
			Path:    "/send-verification-phone",
			Method:  "POST",
			Handler: h.SendVerificationPhone,
		},
		{
			Name:    "core.verify_phone",
			Path:    "/verify-phone",
			Method:  "POST",
			Handler: h.VerifyPhone,
		},

		// 📌 Password Recovery
		{
			Name:    "core.forgot_password",
			Path:    "/forgot-password",
			Method:  "POST",
			Handler: h.ForgotPassword,
		},
		{
			Name:    "core.reset_password",
			Path:    "/reset-password",
			Method:  "POST",
			Handler: h.ResetPassword,
		},

		// 📌 Account Management
		{
			Name:    "core.profile",
			Path:    "/profile",
			Method:  "GET",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.Profile)).ServeHTTP,
		},
		{
			Name:    "core.update_profile",
			Path:    "/profile",
			Method:  "PUT",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.UpdateProfile)).ServeHTTP,
		},
		{
			Name:    "core.change_password",
			Path:    "/change-password",
			Method:  "PUT",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.ChangePassword)).ServeHTTP,
		},
		{
			Name:    "core.check_availability",
			Path:    "/check-availability",
			Method:  "POST",
			Handler: h.CheckAvailability,
		},
		{
			Name:    "core.resend_verification_email",
			Path:    "/resend-verification-email",
			Method:  "POST",
			Handler: h.ResendVerificationEmail,
		},
		{
			Name:    "core.resend_verification_phone",
			Path:    "/resend-verification-phone",
			Method:  "POST",
			Handler: h.ResendVerificationPhone,
		},
	}
	return routes
}
