package ui

import (
	"strings"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// Administrative routes and the console.
//
// Every route an administrator uses to manage something must either have a
// console page, listed in Covered, or a written reason it has none, listed
// in Exempt. A route counts as administrative when IsAdministrative says so.
// tests/integration/ui_coverage_test.go fails when a module adds such a
// route without updating one of the two, so a feature an administrator can
// manage cannot ship without its screen unless the gap is stated here.

// Covered maps an administrative route to the console page that does the
// same job.
var Covered = map[types.RouteName]types.RouteName{
	types.RouteAdminListUsers:        routeUsers,
	types.RouteAdminGetUser:          routeUser,
	types.RouteAdminUpdateUser:       routeUserUpdate,
	types.RouteAdminDeleteUser:       routeUserDelete,
	types.RouteAdminListAuditLogs:    routeAudit,
	types.RouteAdminGetUserAudit:     routeUserActivity,
	types.RouteAdminGetActionAudit:   routeAudit,
	types.RouteAdminCleanupAuditLogs: routeAuditCleanup,

	types.RouteRBACPermissions:     routePermissions,
	types.RouteRBACListRoles:       routeRoles,
	types.RouteRBACCreateRole:      routeRoleCreate,
	types.RouteRBACGetRole:         routeRole,
	types.RouteRBACUpdateRole:      routeRoleUpdate,
	types.RouteRBACDeleteRole:      routeRoleDelete,
	types.RouteRBACGetUserRoles:    routeUserAccess,
	types.RouteRBACSetUserRoles:    routeUserRoles,
	types.RouteRBACListAssignments: routeRole,

	types.RouteRBACOrgListRoles:       routeOrgRoles,
	types.RouteRBACOrgCreateRole:      routeOrgRoleCreate,
	types.RouteRBACOrgGetRole:         routeOrgRole,
	types.RouteRBACOrgUpdateRole:      routeOrgRoleUpdate,
	types.RouteRBACOrgDeleteRole:      routeOrgRoleDelete,
	types.RouteRBACOrgGetMemberRoles:  routeOrgMember,
	types.RouteRBACOrgSetMemberRoles:  routeOrgMemberRoles,
	types.RouteRBACOrgListAssignments: routeOrgRole,

	types.RouteRBACTeamListRoles:       routeTeamMember,
	types.RouteRBACTeamGetMemberRoles:  routeTeamMember,
	types.RouteRBACTeamSetMemberRoles:  routeTeamMemberRoles,
	types.RouteRBACTeamListAssignments: routeTeam,

	types.RouteIDPAdminClientsList:   routeClients,
	types.RouteIDPAdminClientsCreate: routeClientCreate,
	types.RouteIDPAdminClientsGet:    routeClient,
	types.RouteIDPAdminClientsUpdate: routeClientUpdate,
	types.RouteIDPAdminClientsDelete: routeClientDelete,
	types.RouteIDPAdminClientsSecret: routeClientRotate,

	types.RouteInvitationSend: routeInvitationSend,
}

// Exempt lists administrative routes the console deliberately has no page
// for, with the reason. An entry here is a known gap or a route that only
// looks administrative, never a way to skip a screen that is needed.
var Exempt = map[types.RouteName]string{
	types.RouteRBACMyPermissions: "Self-service, for client applications that hide what a user cannot do; not an administrative task.",
}

// IsAdministrative reports whether a route is one the coverage rule applies
// to: its name starts with "admin." or "rbac." or contains ".admin.", or it
// is guarded by the admin middleware. The console's own pages are not.
func IsAdministrative(route config.RouteInfo) bool {
	name := route.Name
	if strings.HasPrefix(name, "ui.") {
		return false
	}
	if strings.HasPrefix(name, "admin.") || strings.HasPrefix(name, "rbac.") || strings.Contains(name, ".admin.") {
		return true
	}
	for _, middleware := range route.Middlewares {
		if middleware == types.MiddlewareAdminAuth {
			return true
		}
	}
	return false
}
