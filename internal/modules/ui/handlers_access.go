package ui

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac"
	"github.com/bete7512/goauth/internal/modules/rbac/access"
	rbacservices "github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
)

// roleScope is where a roles page works: the whole application, or the
// organization in the path.
type roleScope struct {
	Scope access.Scope
	Org   *models.Organization
	Base  string // URL of the roles list
}

// roleScopeOf reads the scope from the path, or answers with an error page.
func (m *UIModule) roleScopeOf(w http.ResponseWriter, r *http.Request) (rbacInternals, *roleScope, bool) {
	_, internals, ok := m.rbacModule()
	if !ok {
		m.unavailable(w, r, "Roles", "rbac")
		return internals, nil, false
	}
	orgID := r.PathValue("orgId")
	if orgID == "" {
		return internals, &roleScope{Scope: access.GlobalScope(), Base: m.base + "/roles"}, true
	}
	if !internals.Organizations {
		m.unavailable(w, r, "Organization roles", "rbac (with Organizations: true)")
		return internals, nil, false
	}
	_, org, ok := m.loadOrg(w, r)
	if !ok {
		return internals, nil, false
	}
	return internals, &roleScope{Scope: access.OrgScope(org.ID), Org: org, Base: m.orgURL(org.ID, "roles")}, true
}

// rolesPage is the roles list of a scope with the new-role form.
type rolesPage struct {
	*roleScope
	Frame       *orgFrame
	Roles       []*rbacservices.RoleView
	Permissions []rbac.PermissionInfo
	Form        rbacservices.RoleInput
	GrantsText  string
}

func (m *UIModule) roles(w http.ResponseWriter, r *http.Request) {
	internals, scope, ok := m.roleScopeOf(w, r)
	if !ok {
		return
	}
	m.showRoles(w, r, http.StatusOK, internals, &rolesPage{roleScope: scope}, "")
}

func (m *UIModule) showRoles(w http.ResponseWriter, r *http.Request, status int, internals rbacInternals, page *rolesPage, message string) {
	opts := models.RoleListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "name", SortDir: "asc"}}
	opts.Normalize(100)
	roles, _, authErr := internals.Roles.List(r.Context(), m.actor(r), page.Scope, opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page.Roles = roles
	page.Permissions = m.hostPermissions()
	nav, title := "roles", "Roles"
	if page.Org != nil {
		frame := m.orgFrame(r, m.orgAdmin(), page.Org, "roles")
		page.Frame = &frame
		nav, title = "orgs", page.Org.Name
	}
	data := m.newView(r, title, nav, page)
	data.Error = message
	m.render(w, r, status, "roles", data)
}

func (m *UIModule) createRole(w http.ResponseWriter, r *http.Request) {
	internals, scope, ok := m.roleScopeOf(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	page := &rolesPage{roleScope: scope, GrantsText: r.PostForm.Get("grants"), Form: rbacservices.RoleInput{
		Key:         strings.TrimSpace(r.PostForm.Get("key")),
		Name:        strings.TrimSpace(r.PostForm.Get("name")),
		Description: strings.TrimSpace(r.PostForm.Get("description")),
		Grants:      splitGrants(r.PostForm.Get("grants")),
	}}
	if _, authErr := internals.Roles.Create(r.Context(), m.actor(r), scope.Scope, page.Form); authErr != nil {
		m.showRoles(w, r, http.StatusUnprocessableEntity, internals, page, authErr.Message)
		return
	}
	m.redirect(w, r, scope.Base+"?notice=role-created")
}

func (m *UIModule) deleteRole(w http.ResponseWriter, r *http.Request) {
	internals, scope, ok := m.roleScopeOf(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	if authErr := internals.Roles.Delete(r.Context(), m.actor(r), scope.Scope, r.PathValue("roleKey")); authErr != nil {
		m.showRoles(w, r, http.StatusUnprocessableEntity, internals, &rolesPage{roleScope: scope}, authErr.Message)
		return
	}
	m.redirect(w, r, scope.Base+"?notice=role-deleted")
}

// --- one role ---

type rolePage struct {
	*roleScope
	Frame       *orgFrame
	Role        *rbacservices.RoleView
	GrantsText  string
	Holders     []roleHolder
	HoldersMore bool
	Permissions []rbac.PermissionInfo
}

type roleHolder struct {
	Assignment *models.RoleAssignment
	User       *models.User
}

func (m *UIModule) role(w http.ResponseWriter, r *http.Request) {
	internals, scope, ok := m.roleScopeOf(w, r)
	if !ok {
		return
	}
	m.showRole(w, r, http.StatusOK, internals, scope, "", "")
}

func (m *UIModule) showRole(w http.ResponseWriter, r *http.Request, status int, internals rbacInternals, scope *roleScope, grantsText, message string) {
	role, authErr := internals.Roles.Get(r.Context(), m.actor(r), scope.Scope, r.PathValue("roleKey"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &rolePage{roleScope: scope, Role: role, GrantsText: grantsText, Permissions: m.hostPermissions()}
	if page.GrantsText == "" {
		page.GrantsText = strings.Join(role.Grants, "\n")
	}
	if !role.Implied {
		opts := models.RoleAssignmentListOpts{ListingOpts: models.ListingOpts{Limit: 50, SortField: "created_at", SortDir: "desc"}, RoleKey: role.Key}
		opts.Normalize(50)
		if assignments, total, authErr := internals.Assignments.List(r.Context(), m.actor(r), scope.Scope, opts); authErr == nil {
			for _, assignment := range assignments {
				user, _ := m.deps.Storage.Core().Users().FindByID(r.Context(), assignment.UserID)
				page.Holders = append(page.Holders, roleHolder{Assignment: assignment, User: user})
			}
			page.HoldersMore = total > int64(len(assignments))
		}
	}
	nav := "roles"
	if scope.Org != nil {
		frame := m.orgFrame(r, m.orgAdmin(), scope.Org, "roles")
		page.Frame = &frame
		nav = "orgs"
	}
	data := m.newView(r, role.Name, nav, page)
	data.Error = message
	m.render(w, r, status, "role", data)
}

func (m *UIModule) updateRole(w http.ResponseWriter, r *http.Request) {
	internals, scope, ok := m.roleScopeOf(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	description := strings.TrimSpace(r.PostForm.Get("description"))
	grants := splitGrants(r.PostForm.Get("grants"))
	key := r.PathValue("roleKey")
	if _, authErr := internals.Roles.Update(r.Context(), m.actor(r), scope.Scope, key, rbacservices.RolePatch{Name: &name, Description: &description, Grants: &grants}); authErr != nil {
		m.showRole(w, r, http.StatusUnprocessableEntity, internals, scope, r.PostForm.Get("grants"), authErr.Message)
		return
	}
	m.redirect(w, r, scope.Base+"/"+url.PathEscape(key)+"?notice=role-saved")
}

// --- permissions ---

type permissionRow struct {
	Permission  string
	Description string
	Roles       []*rbacservices.RoleView // application-wide roles that grant it
}

type permissionsPage struct {
	Rows   []permissionRow
	Wide   []*rbacservices.RoleView // roles with a wildcard that reaches every permission
	Groups []string
}

func (m *UIModule) permissions(w http.ResponseWriter, r *http.Request) {
	_, internals, ok := m.rbacModule()
	if !ok {
		m.unavailable(w, r, "Permissions", "rbac")
		return
	}
	opts := models.RoleListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "name", SortDir: "asc"}}
	opts.Normalize(100)
	roles, _, authErr := internals.Roles.List(r.Context(), m.actor(r), access.GlobalScope(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &permissionsPage{}
	for _, role := range roles {
		if access.ParseSetLenient(role.Grants).Allows("goauth-ui-probe:any") {
			page.Wide = append(page.Wide, role)
		}
	}
	for _, permission := range m.hostPermissions() {
		row := permissionRow{Permission: permission.Permission, Description: permission.Description}
		for _, role := range roles {
			if access.ParseSetLenient(role.Grants).Allows(permission.Permission) && !contains(page.Wide, role) {
				row.Roles = append(row.Roles, role)
			}
		}
		page.Rows = append(page.Rows, row)
	}
	m.render(w, r, http.StatusOK, "permissions", m.newView(r, "Permissions", "permissions", page))
}

// hostPermissions is the catalog without GoAuth's own permissions.
func (m *UIModule) hostPermissions() []rbac.PermissionInfo {
	module, _, ok := m.rbacModule()
	if !ok {
		return nil
	}
	var out []rbac.PermissionInfo
	for _, permission := range module.Catalog() {
		resource, _, _ := strings.Cut(permission.Permission, ":")
		if !access.IsReserved(resource) {
			out = append(out, permission)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Permission < out[j].Permission })
	return out
}

func contains(roles []*rbacservices.RoleView, role *rbacservices.RoleView) bool {
	for _, item := range roles {
		if item.Key == role.Key {
			return true
		}
	}
	return false
}
