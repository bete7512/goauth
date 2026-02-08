package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type AdminHandler struct {
	deps    config.ModuleDependencies
	service services.AdminService
}

func NewAdminHandler(deps config.ModuleDependencies, service services.AdminService) *AdminHandler {
	return &AdminHandler{
		deps:    deps,
		service: service,
	}
}

// GetRoutes returns all admin routes
func (h *AdminHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:        string(types.RouteAdminListUsers),
			Path:        "/admin/users",
			Method:      http.MethodGet,
			Handler:     h.ListUsers,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminGetUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.GetUser,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminUpdateUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodPut,
			Handler:     h.UpdateUser,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminDeleteUser),
			Path:        "/admin/users/{id}",
			Method:      http.MethodDelete,
			Handler:     h.DeleteUser,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
	}
}
