package api

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/examples/rbac/internal/platform"
	"github.com/bete7512/goauth/pkg/modules/rbac"
)

// Routes registers the tracker's routes on mux. requireAuth is GoAuth's
// authentication middleware; every route needs a signed-in caller.
//
// Each block shows one way to say where a check runs:
//
//	rbac.Global()       application-wide roles only
//	(no option)         the organization the caller's token is signed in to
//	rbac.OrgParam(...)  the organization named in the path
//	rbac.OrgFrom(...)   the organization that owns the resource
//	rbac.TeamParam(...) the team named in the path
//	rbac.TeamFrom(...)  the team that owns the resource
//	authz.Check(...)    a check made in code, inside a handler
func (a *API) Routes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	guard := func(pattern string, check func(http.Handler) http.Handler, handler http.HandlerFunc) {
		mux.Handle(pattern, requireAuth(check(handler)))
	}
	signedIn := func(next http.Handler) http.Handler { return next }

	// 1. Platform-wide: only an application-wide role can export reports,
	//    whatever organization the caller is signed in to. Support staff
	//    (the global "support" role) and super admins can.
	guard("GET /api/reports/usage", a.authz.Require(platform.PermReportExport, rbac.Global()), a.usageReport)

	// 2. The caller's current organization: Resource maps the method to an
	//    action (GET → invoice:read, POST → invoice:create, ...). The token
	//    names the organization after POST /auth/org/switch.
	invoices := a.authz.Resource("invoice")
	guard("GET /api/invoices", invoices, a.listInvoices)
	guard("POST /api/invoices", invoices, a.createInvoice)

	// 3. The organization that owns the invoice in the path, plus a rule of
	//    the application's own: nobody approves an invoice they created
	//    (OnlyIf can refuse what the roles allow).
	guard("POST /api/invoices/{id}/approve", a.authz.Require(platform.PermInvoiceApprove,
		rbac.OrgFrom(a.invoiceOrg),
		rbac.OnlyIf(a.notInvoiceCreator),
	), a.approveInvoice)

	// 4. The organization named in the path, whatever the token says.
	guard("GET /api/orgs/{orgId}/billing", a.authz.Require("invoice:read", rbac.OrgParam("orgId")), a.billingSummary)

	// 5. The team named in the path. A role held on a team counts in every
	//    team beneath it, and organization roles count in all its teams.
	teamProjects := a.authz.Resource("project", rbac.TeamParam("teamId"))
	guard("GET /api/teams/{teamId}/projects", teamProjects, a.listTeamProjects)
	guard("POST /api/teams/{teamId}/projects", teamProjects, a.createProject)

	// 6. The team that owns the project in the path.
	project := a.authz.Resource("project", rbac.TeamFrom(a.projectTeam))
	guard("GET /api/projects/{id}", project, a.getProject)
	guard("PATCH /api/projects/{id}", project, a.renameProject)

	// 7. A list that spans teams: the handler asks rbac which teams of the
	//    organization the caller may read projects in (TeamsWhere).
	guard("GET /api/projects", signedIn, a.listProjects)

	// 8. A check made in code. Archiving is decided inside the handler,
	//    after the project is loaded, with authz.Check and rbac.InTeam.
	guard("POST /api/projects/{id}/archive", signedIn, a.archiveProject)

	// 9. AllowIf lets a request through that the roles refuse: whoever a
	//    task is assigned to may complete it, even without task:update.
	guard("POST /api/tasks/{id}/complete", a.authz.Require("task:update",
		rbac.TeamFrom(a.taskTeam),
		rbac.AllowIf(a.isAssignee),
	), a.completeTask)
}

// notInvoiceCreator is the four-eyes rule for approvals.
func (a *API) notInvoiceCreator(_ context.Context, c rbac.Check) bool {
	inv, err := a.store.Invoice(c.Request.PathValue("id"))
	return err == nil && inv.CreatedBy != c.UserID
}

// isAssignee lets the person a task is assigned to complete it.
func (a *API) isAssignee(_ context.Context, c rbac.Check) bool {
	t, err := a.store.Task(c.Request.PathValue("id"))
	return err == nil && t.AssigneeID != "" && t.AssigneeID == c.UserID
}
