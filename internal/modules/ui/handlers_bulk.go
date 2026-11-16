package ui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// maxBulk is the most users one bulk action may name: a page of the list at
// its largest.
const maxBulk = 100

// bulkActions are the actions the users list can apply to its selection.
var bulkActions = map[string]bool{"deactivate": true, "activate": true, "sign-out": true, "delete": true}

// bulkUsers applies one action to the users ticked on the list. Each user
// goes through the same admin operation as their own page, so the rules
// (super admin only, events) are the same. The signed-in administrator is
// always skipped.
func (m *UIModule) bulkUsers(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	action := r.PostForm.Get("action")
	ids := uniqueIDs(r.PostForm["ids"])
	back := m.base + "/users"
	if q := strings.TrimSpace(r.PostForm.Get("q")); q != "" {
		back += "?q=" + url.QueryEscape(q) + "&"
	} else {
		back += "?"
	}
	switch {
	case !bulkActions[action]:
		m.renderError(w, r, http.StatusBadRequest, "Choose what to do with the selected users.")
		return
	case len(ids) == 0:
		m.redirect(w, r, back+"notice=bulk-none")
		return
	case len(ids) > maxBulk:
		m.renderError(w, r, http.StatusBadRequest, "Select at most "+strconv.Itoa(maxBulk)+" users at a time.")
		return
	}
	self := visitorFrom(r.Context()).User.ID
	done, failed := 0, 0
	for _, id := range ids {
		if id == self {
			failed++
			continue
		}
		if authErr := m.bulkUser(r.Context(), action, id); authErr != nil {
			if authErr.StatusCode >= http.StatusInternalServerError {
				m.deps.Logger.Error("ui: bulk action failed", "action", action, "user_id", id, "error", authErr.Error())
			}
			failed++
			continue
		}
		done++
	}
	notice := "bulk-done"
	if failed > 0 {
		notice = "bulk-partial"
	}
	m.redirect(w, r, back+"notice="+notice+"&n="+strconv.Itoa(done)+"&skipped="+strconv.Itoa(failed))
}

func (m *UIModule) bulkUser(ctx context.Context, action, id string) *types.GoAuthError {
	switch action {
	case "sign-out":
		return m.admin.SignOutEverywhere(ctx, id)
	case "delete":
		return m.admin.DeleteUser(ctx, id)
	}
	user, authErr := m.admin.GetUser(ctx, id)
	if authErr != nil {
		return authErr
	}
	active := action == "activate"
	if user.Active == active {
		return nil
	}
	edited := *user
	edited.Active = active
	return m.admin.UpdateUser(ctx, &edited)
}

func uniqueIDs(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// --- CSV exports ---

// exportBatch is how many rows an export reads at a time.
const exportBatch = 500

// csvWriter writes a download. Every cell is guarded against spreadsheet
// formula injection.
type csvWriter struct {
	out *csv.Writer
	err error
}

func (m *UIModule) startCSV(w http.ResponseWriter, name string, header ...string) *csvWriter {
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+name+"-"+timeNow().UTC().Format("20060102-150405")+`.csv"`)
	h.Set("Cache-Control", "no-store")
	c := &csvWriter{out: csv.NewWriter(w)}
	c.row(header...)
	return c
}

func (c *csvWriter) row(cells ...string) {
	if c.err != nil {
		return
	}
	for i, cell := range cells {
		cells[i] = csvSafe(cell)
	}
	c.err = c.out.Write(cells)
}

func (c *csvWriter) finish() error {
	c.out.Flush()
	if c.err != nil {
		return c.err
	}
	return c.out.Error()
}

// csvSafe stops a spreadsheet from reading a cell as a formula: a value that
// starts with =, +, -, @, a tab or a carriage return gets a leading quote.
func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

func csvTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func csvBool(b bool) string { return strconv.FormatBool(b) }

// exportUsers downloads every user matching the list's search.
func (m *UIModule) exportUsers(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	page := func(offset int) ([]*models.User, int64, *types.GoAuthError) {
		opts := models.UserListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: exportBatch, SortField: "created_at", SortDir: "asc"}, Query: query}
		opts.Normalize(exportBatch)
		return m.admin.ListUsers(r.Context(), opts)
	}
	first, _, authErr := page(0)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	out := m.startCSV(w, "users", "id", "email", "username", "name", "phone_number", "active", "email_verified", "phone_number_verified", "super_admin", "locked_until", "last_login_at", "created_at")
	err := exportPages(first, page, func(u *models.User) {
		out.row(u.ID, u.Email, u.Username, u.Name, u.PhoneNumber, csvBool(u.Active), csvBool(u.EmailVerified), csvBool(u.PhoneNumberVerified), csvBool(u.IsSuperAdmin), csvTime(u.LockedUntil), csvTime(u.LastLoginAt), csvTime(&u.CreatedAt))
	})
	m.finishExport(r, "users", out, err)
}

// exportOrgs downloads every organization matching the list's search.
func (m *UIModule) exportOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, ok := m.orgService(w, r)
	if !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	page := func(offset int) ([]*models.Organization, int64, *types.GoAuthError) {
		opts := models.OrganizationListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: exportBatch, SortField: "created_at", SortDir: "asc"}, Query: query}
		opts.Normalize(exportBatch)
		return orgs.ListOrganizations(r.Context(), opts)
	}
	first, _, authErr := page(0)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	out := m.startCSV(w, "organizations", "id", "name", "slug", "owner_id", "active", "created_at")
	err := exportPages(first, page, func(o *models.Organization) {
		out.row(o.ID, o.Name, o.Slug, o.OwnerID, csvBool(o.Active), csvTime(&o.CreatedAt))
	})
	m.finishExport(r, "organizations", out, err)
}

// exportAudit downloads the audit events the log's filters select.
func (m *UIModule) exportAudit(w http.ResponseWriter, r *http.Request) {
	auditService := m.auditService()
	if auditService == nil {
		m.unavailable(w, r, "Audit records", "audit")
		return
	}
	query := r.URL.Query()
	action, userID := strings.TrimSpace(query.Get("action")), strings.TrimSpace(query.Get("user"))
	page := func(offset int) ([]*models.AuditLog, int64, *types.GoAuthError) {
		opts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: exportBatch, SortField: "created_at", SortDir: "desc"}}
		opts.Normalize(exportBatch)
		switch {
		case userID != "":
			return auditService.GetUserAuditLogs(r.Context(), userID, opts)
		case action != "":
			return auditService.GetAuditLogsByAction(r.Context(), action, opts)
		default:
			return auditService.ListAllAuditLogs(r.Context(), opts)
		}
	}
	first, _, authErr := page(0)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	out := m.startCSV(w, "audit-log", "id", "created_at", "action", "severity", "actor_id", "actor_type", "target_type", "target_id", "details", "ip_address", "user_agent")
	err := exportPages(first, page, func(e *models.AuditLog) {
		out.row(e.ID, csvTime(&e.CreatedAt), e.Action, e.Severity, e.ActorID, e.ActorType, deref(e.TargetType), deref(e.TargetID), e.Details, e.IPAddress, e.UserAgent)
	})
	m.finishExport(r, "audit", out, err)
}

// exportPages walks a list from its first page until a short page.
func exportPages[T any](first []T, page func(offset int) ([]T, int64, *types.GoAuthError), write func(T)) *types.GoAuthError {
	batch, offset := first, 0
	for {
		for _, item := range batch {
			write(item)
		}
		if len(batch) < exportBatch {
			return nil
		}
		offset += len(batch)
		next, _, authErr := page(offset)
		if authErr != nil {
			return authErr
		}
		batch = next
	}
}

// finishExport ends a download. Once rows are written the status is sent,
// so a failure part way can only be logged; the file then ends early.
func (m *UIModule) finishExport(r *http.Request, what string, out *csvWriter, authErr *types.GoAuthError) {
	if authErr != nil {
		m.deps.Logger.Error("ui: export stopped early", "export", what, "error", authErr.Error())
		out.row("ERROR: the export stopped early and is incomplete; download it again")
	}
	if err := out.finish(); err != nil {
		m.deps.Logger.Warn("ui: export was not delivered", "export", what, "path", r.URL.Path, "error", err)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
