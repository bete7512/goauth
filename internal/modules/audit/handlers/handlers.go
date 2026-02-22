package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/audit/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type AuditHandler struct {
	deps    config.ModuleDependencies
	service services.AuditService
}

func NewAuditHandler(deps config.ModuleDependencies, service services.AuditService) *AuditHandler {
	return &AuditHandler{
		deps:    deps,
		service: service,
	}
}

// GetRoutes returns all audit routes
func (h *AuditHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		// User self-service routes
		{
			Name:        string(types.RouteAuditMyLogs),
			Path:        "/me/audit",
			Method:      http.MethodGet,
			Handler:     h.GetMyAuditLogs,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth}, // Requires authentication
		},
		{
			Name:        string(types.RouteAuditMyLogins),
			Path:        "/me/audit/logins",
			Method:      http.MethodGet,
			Handler:     h.GetMyLogins,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        string(types.RouteAuditMyChanges),
			Path:        "/me/audit/changes",
			Method:      http.MethodGet,
			Handler:     h.GetMyChanges,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        string(types.RouteAuditMySecurity),
			Path:        "/me/audit/security",
			Method:      http.MethodGet,
			Handler:     h.GetMySecurity,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth},
		},
		{
			Name:        string(types.RouteAdminListAuditLogs),
			Path:        "/admin/audit",
			Method:      http.MethodGet,
			Handler:     h.AdminListAuditLogs,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminGetUserAudit),
			Path:        "/admin/audit/users/{id}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetUserAudit,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminGetActionAudit),
			Path:        "/admin/audit/actions/{action}",
			Method:      http.MethodGet,
			Handler:     h.AdminGetActionAudit,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
		{
			Name:        string(types.RouteAdminCleanupAuditLogs),
			Path:        "/admin/audit/cleanup",
			Method:      http.MethodPost,
			Handler:     h.AdminCleanupLogs,
			Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth},
		},
	}
}
