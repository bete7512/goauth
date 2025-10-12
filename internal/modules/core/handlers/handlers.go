package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreHandler struct {
	CoreService *core_services.CoreService
	deps        config.ModuleDependencies
}

func NewCoreHandler(coreService *core_services.CoreService, deps config.ModuleDependencies) *CoreHandler {
	return &CoreHandler{
		CoreService: coreService,
		deps:        deps,
	}
}

func (h *CoreHandler) GetRoutes() []config.RouteInfo {
	// register routes here with unique names
	authMiddleware := middlewares.NewAuthMiddleware(h.deps.Config, h.deps.SecurityManager)
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
			Path:    "/availability/email",
			Method:  "POST",
			Handler: h.CheckEmailAvailability,
		},
		{
			Name:    "core.check_username_availability",
			Path:    "/availability/username",
			Method:  "POST",
			Handler: h.CheckUsernameAvailability,
		},
		{
			Name:    "core.check_phone_availability",
			Path:    "/availability/phone",
			Method:  "POST",
			Handler: h.CheckPhoneAvailability,
		},
	}
	return routes
}
