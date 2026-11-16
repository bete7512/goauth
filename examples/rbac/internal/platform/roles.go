package platform

import "github.com/bete7512/goauth/pkg/modules/rbac"

// Permissions the tracker checks. Most are declared where a route uses
// them (Require, Resource); the ones only checked in code are declared here
// so they appear in the console's permission catalog with a description.
const (
	PermReportExport   = "report:export"
	PermInvoiceApprove = "invoice:approve"
	PermProjectArchive = "project:archive"
)

// Roles are defined in code, so they are versioned with the application.
// Administrators can still create more in the console (/admin/roles), per
// organization or application-wide.
//
// Besides these, some roles exist without any configuration:
//
//   - super_admin: every user with the super admin flag; everything.
//   - owner / admin: an organization's owner and admins hold every
//     permission of the application inside their organization.
//   - member: every other organization member; nothing by default.
//   - lead (team scope): a team's leads hold every permission of the
//     application in that team and every team beneath it.
var Roles = []rbac.Role{
	{
		// Platform staff who answer tickets: read anything, export reports,
		// change nothing. Held application-wide.
		Key: "support", Name: "Support", Scope: rbac.ScopeGlobal,
		Description: "Read-only access to every organization, plus report exports",
		Grants:      []string{"*:read", PermReportExport},
	},
	{
		// Finance people inside one customer organization.
		Key: "billing", Name: "Billing", Scope: rbac.ScopeOrg,
		Description: "Creates and edits the organization's invoices",
		Grants:      []string{"invoice:*"},
	},
	{
		Key: "accountant", Name: "Accountant", Scope: rbac.ScopeOrg,
		Description: "Reads and approves invoices; cannot create them",
		Grants:      []string{"invoice:read", PermInvoiceApprove},
	},
	{
		// Engineers, given on a team. Through the team tree it also covers
		// every team beneath the one it is held on.
		Key: "developer", Name: "Developer", Scope: rbac.ScopeTeam,
		Description: "Works on the team's projects and tasks",
		Grants:      []string{"project:read", "project:update", "task:*"},
	},
	{
		// No scope: assignable application-wide, per organization or per team.
		Key: "viewer", Name: "Viewer",
		Description: "Reads everything in the scope it is held in",
		Grants:      []string{"*:read"},
	},
}
