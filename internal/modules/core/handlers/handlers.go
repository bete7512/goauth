package handlers

import (
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
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
	routes := []config.RouteInfo{
		// 📌 Core Auth Routes
		{
			Name:    string(types.RouteSignup),
			Path:    "/signup",
			Method:  "POST",
			Handler: h.Signup,
		},
		{
			Name:    string(types.RouteLogin),
			Path:    "/login",
			Method:  "POST",
			Handler: h.Login,
		},
		{
			Name:        string(types.RouteLogout),
			Path:        "/logout",
			Method:      "POST",
			Handler:     h.Logout,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteMe),
			Path:        "/me",
			Method:      "GET",
			Handler:     h.Me,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteUpdateProfile),
			Path:        "/profile",
			Method:      "PUT",
			Handler:     h.UpdateProfile,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:        string(types.RouteChangePassword),
			Path:        "/change-password",
			Method:      "PUT",
			Handler:     h.ChangePassword,
			Middlewares: []string{string(types.MiddlewareAuth)},
		},
		{
			Name:    string(types.RouteCheckAvailability),
			Path:    "/availability/email",
			Method:  "POST",
			Handler: h.CheckEmailAvailability,
		},
		{
			Name:    string(types.RouteCheckUsernameAvailability),
			Path:    "/availability/username",
			Method:  "POST",
			Handler: h.CheckUsernameAvailability,
		},
		{
			Name:    string(types.RouteCheckPhoneAvailability),
			Path:    "/availability/phone",
			Method:  "POST",
			Handler: h.CheckPhoneAvailability,
		},
	}
	return routes
}
