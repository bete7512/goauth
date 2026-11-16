package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	rbacservices "github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Fragment IDs htmx swaps in place of a whole page.
const (
	usersTable = "users-table"
	auditTable = "audit-table"
)

type dashboardPage struct {
	Users        int64
	AuditEvents  int64
	Roles        int64
	Orgs         int64
	RecentUsers  []*models.User
	RecentEvents []*models.AuditLog
	Charts       []*chart
}

func (m *UIModule) dashboard(w http.ResponseWriter, r *http.Request) {
	page := &dashboardPage{}
	opts := models.UserListOpts{ListingOpts: models.ListingOpts{Limit: 5, SortField: "created_at", SortDir: "desc"}}
	opts.Normalize(5)
	users, total, authErr := m.admin.ListUsers(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page.Users, page.RecentUsers = total, users

	if auditService := m.auditService(); auditService != nil {
		auditOpts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Limit: 8, SortField: "created_at", SortDir: "desc"}}
		auditOpts.Normalize(8)
		if events, count, authErr := auditService.ListAllAuditLogs(r.Context(), auditOpts); authErr == nil {
			page.AuditEvents, page.RecentEvents = count, events
		}
	}
	if _, internals, ok := m.rbacModule(); ok {
		roleOpts := models.RoleListOpts{ListingOpts: models.ListingOpts{Limit: 1}}
		roleOpts.Normalize(1)
		if _, count, authErr := internals.Roles.List(r.Context(), m.actor(r), access.GlobalScope(), roleOpts); authErr == nil {
			page.Roles = count
		}
	}
	if orgs := m.orgAdmin(); orgs != nil {
		orgOpts := models.OrganizationListOpts{ListingOpts: models.ListingOpts{Limit: 1}}
		orgOpts.Normalize(1)
		if _, count, authErr := orgs.ListOrganizations(r.Context(), orgOpts); authErr == nil {
			page.Orgs = count
		}
	}
	page.Charts = m.overviewCharts(r)
	m.render(w, r, http.StatusOK, "dashboard", m.newView(r, "Overview", "dashboard", page))
}

type usersPage struct {
	Query string
	Users []*models.User
	Pager pager
}

func (m *UIModule) users(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.UserListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}, Query: query}
	opts.Normalize(m.config.PageSize)
	users, total, authErr := m.admin.ListUsers(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	params := url.Values{}
	if query != "" {
		params.Set("q", query)
	}
	page := &usersPage{Query: query, Users: users, Pager: pager{
		Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/users", Query: params.Encode(), Target: usersTable,
	}}
	m.render(w, r, http.StatusOK, "users", m.newView(r, "Users", "users", page), usersTable)
}

// actor is the signed-in administrator, for services that check permissions.
func (m *UIModule) actor(r *http.Request) *rbacservices.Actor {
	return &rbacservices.Actor{Principal: visitorFrom(r.Context()).Principal}
}

// serviceError shows a service failure as a page.
func (m *UIModule) serviceError(w http.ResponseWriter, r *http.Request, authErr *types.GoAuthError) {
	status := authErr.StatusCode
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusInternalServerError
	}
	message := authErr.Message
	switch {
	case status == http.StatusNotFound:
		message = "We could not find what you were looking for."
	case status >= http.StatusInternalServerError:
		m.deps.Logger.Error("ui: request failed", "path", r.URL.Path, "error", authErr.Error())
		message = "Something went wrong. Try again."
	}
	m.renderError(w, r, status, message)
}

func displayName(user *models.User) string {
	if name := strings.TrimSpace(user.Name); name != "" {
		return name
	}
	if name := strings.TrimSpace(user.FirstName + " " + user.LastName); name != "" {
		return name
	}
	return user.Email
}
