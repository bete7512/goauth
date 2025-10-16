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
			Middlewares: []string{"core.auth"},
		},
		{
			Name:    "core.me",
			Path:    "/me",
			Method:  "GET",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.Me)).ServeHTTP,
			Middlewares: []string{"core.auth"},
		},

		// 📌 Account Management
		{
			Name:    "core.profile",
			Path:    "/profile",
			Method:  "GET",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.Profile)).ServeHTTP,
			Middlewares: []string{"core.user.auth","admin.admin.auth"},
		},
		{
			Name:    "core.update_profile",
			Path:    "/profile",
			Method:  "PUT",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.UpdateProfile)).ServeHTTP,
			Middlewares: []string{"core.user.auth","admin.admin.auth"},
		},
		{
			Name:    "core.change_password",
			Path:    "/change-password",
			Method:  "PUT",
			Handler: authMiddleware.AuthMiddleware(http.HandlerFunc(h.ChangePassword)).ServeHTTP,
			Middlewares: []string{"core.auth"},
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
