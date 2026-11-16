package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type rbacInternals = rbac.Internals

// --- audit log ---

type auditPage struct {
	Action string
	UserID string
	Events []*models.AuditLog
	// Actors are the users named on this page, by ID. A user who has since
	// been deleted is absent and shown by ID.
	Actors map[string]*models.User
	Pager  pager
}

func (m *UIModule) auditLog(w http.ResponseWriter, r *http.Request) {
	auditService := m.auditService()
	if auditService == nil {
		m.renderError(w, r, http.StatusNotFound, "The audit log is not enabled. Register the audit module to record events.")
		return
	}
	query := r.URL.Query()
	page := &auditPage{Action: strings.TrimSpace(query.Get("action")), UserID: strings.TrimSpace(query.Get("user"))}
	offset, _ := strconv.Atoi(query.Get("offset"))
	opts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}}
	opts.Normalize(m.config.PageSize)

	var (
		total   int64
		authErr *types.GoAuthError
	)
	switch {
	case page.UserID != "":
		page.Events, total, authErr = auditService.GetUserAuditLogs(r.Context(), page.UserID, opts)
	case page.Action != "":
		page.Events, total, authErr = auditService.GetAuditLogsByAction(r.Context(), page.Action, opts)
	default:
		page.Events, total, authErr = auditService.ListAllAuditLogs(r.Context(), opts)
	}
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page.Actors = m.actors(r, page.Events)
	params := url.Values{}
	if page.Action != "" {
		params.Set("action", page.Action)
	}
	if page.UserID != "" {
		params.Set("user", page.UserID)
	}
	page.Pager = pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/audit", Query: params.Encode(), Target: auditTable}
	m.render(w, r, http.StatusOK, "audit", m.newView(r, "Audit log", "audit", page), auditTable)
}

// actors loads the users who performed the listed events, once each. A page
// holds at most PageSize events, so this is at most that many lookups.
func (m *UIModule) actors(r *http.Request, events []*models.AuditLog) map[string]*models.User {
	actors := map[string]*models.User{}
	for _, event := range events {
		if event.ActorID == "" {
			continue
		}
		if _, seen := actors[event.ActorID]; seen {
			continue
		}
		user, err := m.deps.Storage.Core().Users().FindByID(r.Context(), event.ActorID)
		if err != nil || user == nil {
			actors[event.ActorID] = nil
			continue
		}
		actors[event.ActorID] = user
	}
	return actors
}

// cleanupAudit deletes events older than the audit module's retention
// periods, as the cleanup endpoint does.
func (m *UIModule) cleanupAudit(w http.ResponseWriter, r *http.Request) {
	auditService := m.auditService()
	if auditService == nil {
		m.renderError(w, r, http.StatusNotFound, "The audit log is not enabled.")
		return
	}
	if authErr := auditService.CleanupOldLogs(r.Context()); authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	m.redirect(w, r, m.base+"/audit?notice=audit-cleaned")
}

// --- account ---

type accountPage struct {
	User   *models.User
	Events []*models.AuditLog
}

func (m *UIModule) account(w http.ResponseWriter, r *http.Request) {
	v := visitorFrom(r.Context())
	page := &accountPage{User: v.User}
	if auditService := m.auditService(); auditService != nil {
		opts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Limit: 10, SortField: "created_at", SortDir: "desc"}}
		opts.Normalize(10)
		if events, _, authErr := auditService.GetMyAuditLogs(r.Context(), v.User.ID, opts); authErr == nil {
			page.Events = events
		}
	}
	m.render(w, r, http.StatusOK, "account", m.newView(r, "Your account", "account", page))
}
