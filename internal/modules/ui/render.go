package ui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

// --- assets ---

type asset struct {
	body        []byte
	contentType string
	version     string
}

type assetSet struct {
	files map[string]asset
}

var assetTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
}

func loadAssets(fsys fs.FS) (*assetSet, error) {
	set := &assetSet{files: map[string]asset{}}
	entries, err := fs.ReadDir(fsys, "assets")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		contentType, ok := assetTypes[path.Ext(entry.Name())]
		if entry.IsDir() || !ok {
			continue
		}
		body, err := fs.ReadFile(fsys, "assets/"+entry.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		set.files[entry.Name()] = asset{body: body, contentType: contentType, version: hex.EncodeToString(sum[:6])}
	}
	for _, required := range []string{"app.css", "htmx.min.js", "app.js"} {
		if _, ok := set.files[required]; !ok {
			return nil, fmt.Errorf("asset %s is missing", required)
		}
	}
	return set, nil
}

// serveAsset serves an embedded file. A request that names the current
// version may be cached for a year; any other is revalidated.
func (m *UIModule) serveAsset(w http.ResponseWriter, r *http.Request) {
	file, ok := m.assets.files[r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("v") == file.version {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", file.contentType)
	w.Header().Set("ETag", `"`+file.version+`"`)
	if r.Header.Get("If-None-Match") == `"`+file.version+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(file.body)
}

func (m *UIModule) assetURL(name string) string {
	return m.base + "/assets/" + name + "?v=" + m.assets.files[name].version
}

// --- templates ---

// pageSet holds one template per page, each parsed together with the
// layout and the shared partials so that block names never collide.
type pageSet struct {
	pages map[string]*template.Template
}

func loadPages(fsys fs.FS, funcs template.FuncMap) (*pageSet, error) {
	shared := []string{"templates/layout.html", "templates/partials.html"}
	entries, err := fs.ReadDir(fsys, "templates")
	if err != nil {
		return nil, err
	}
	set := &pageSet{pages: map[string]*template.Template{}}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".html")
		if name == "layout" || name == "partials" {
			continue
		}
		page, err := template.New(name).Funcs(funcs).ParseFS(fsys, append(shared, "templates/"+entry.Name())...)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		set.pages[name] = page
	}
	return set, nil
}

// view is the data every page receives. Page holds what is specific to it.
type view struct {
	Title     string
	Product   string
	Base      string
	Nav       string
	Visitor   *visitor
	Admin     bool
	UserPages bool
	Features  features
	Menu      []navGroup
	Notice    string
	Error     string
	CSS       string
	JS        string
	HTMX      string
	Page      any
}

// features says which optional modules are registered, so pages offer only
// what works.
type features struct {
	Audit         bool
	Roles         bool
	OrgRoles      bool // rbac with Organizations
	Organizations bool
	Invitations   bool
	Clients       bool // identity provider
	Sessions      bool // session strategy
	LinkedAccount bool // oauth or saml accounts store
	TwoFactor     bool
	Passkeys      bool
	Email         bool // core can send reset and verification emails
}

func (m *UIModule) features() features {
	_, internals, roles := m.rbacModule()
	store := m.deps.Storage
	_, oauth := m.deps.Lookup(string(types.OAuthModule))
	_, twoFactor := m.deps.Lookup(string(types.TwoFactorModule))
	_, passkeys := m.deps.Lookup(string(types.PasskeysModule))
	_, notification := m.deps.Lookup(string(types.NotificationModule))
	return features{
		Audit:         m.auditService() != nil,
		Roles:         roles,
		OrgRoles:      roles && internals.Organizations,
		Organizations: m.orgAdmin() != nil,
		Invitations:   m.invitationService() != nil,
		Clients:       m.idpService() != nil,
		Sessions:      m.deps.Config.Security.AuthStrategy == types.StrategySession && store.Session() != nil,
		LinkedAccount: oauth && store.OAuth() != nil,
		TwoFactor:     twoFactor && store.TwoFactorAuth() != nil,
		Passkeys:      passkeys && store.Passkeys() != nil,
		Email:         notification && m.coreService() != nil,
	}
}

// navGroup is a titled block of the sidebar.
type navGroup struct {
	Label string
	Items []navItem
}

// navItem is one sidebar entry. A disabled entry stays visible so that
// administrators can see what GoAuth offers; its hint names the module to
// register.
type navItem struct {
	Key, Label, Href, Icon string
	Enabled                bool
	Hint                   string
}

func (m *UIModule) menu(f features, userPages bool) []navGroup {
	off := func(module string) string { return "Register the " + module + " module to use this" }
	return []navGroup{
		{Label: "", Items: []navItem{{Key: "dashboard", Label: "Overview", Href: m.base, Icon: "home", Enabled: true}}},
		{Label: "People", Items: []navItem{
			{Key: "users", Label: "Users", Href: m.base + "/users", Icon: "users", Enabled: true},
			{Key: "orgs", Label: "Organizations", Href: m.base + "/orgs", Icon: "building", Enabled: f.Organizations, Hint: off("organization")},
			{Key: "invitations", Label: "Invitations", Href: m.base + "/invitations", Icon: "mail", Enabled: f.Invitations, Hint: off("invitation")},
			{Key: "teams", Label: "Teams", Icon: "team", Hint: "Nested teams are planned; they will appear here when the team module ships"},
		}},
		{Label: "Access", Items: []navItem{
			{Key: "roles", Label: "Roles", Href: m.base + "/roles", Icon: "key", Enabled: f.Roles, Hint: off("rbac")},
			{Key: "permissions", Label: "Permissions", Href: m.base + "/permissions", Icon: "shield", Enabled: f.Roles, Hint: off("rbac")},
		}},
		{Label: "Applications", Items: []navItem{
			{Key: "clients", Label: "OIDC clients", Href: m.base + "/clients", Icon: "grid", Enabled: f.Clients, Hint: off("idp (identity provider)")},
		}},
		{Label: "Activity", Items: []navItem{
			{Key: "audit", Label: "Audit log", Href: m.base + "/audit", Icon: "list", Enabled: f.Audit, Hint: off("audit")},
		}},
		{Label: "System", Items: []navItem{
			{Key: "settings", Label: "Settings", Href: m.base + "/settings", Icon: "gear", Enabled: true},
		}},
	}
}

func (m *UIModule) newView(r *http.Request, title, nav string, page any) *view {
	v := visitorFrom(r.Context())
	f := m.features()
	data := &view{
		Title:     title,
		Product:   m.config.Title,
		Base:      m.base,
		Nav:       nav,
		Visitor:   v,
		Admin:     v.admin(),
		UserPages: m.config.UserPages,
		Features:  f,
		Notice:    notices[r.URL.Query().Get("notice")],
		CSS:       m.assetURL("app.css"),
		JS:        m.assetURL("app.js"),
		HTMX:      m.assetURL("htmx.min.js"),
		Page:      page,
	}
	if data.Admin {
		data.Menu = m.menu(f, m.config.UserPages)
	}
	return data
}

// unavailable answers a page whose module is not registered.
func (m *UIModule) unavailable(w http.ResponseWriter, r *http.Request, what, module string) {
	m.renderError(w, r, http.StatusNotFound, what+" are not enabled. Register the "+module+" module to manage them here.")
}

// notices are the only texts a redirect can ask a page to show. A message
// is never taken from the URL, so a link cannot make the console display
// words of someone else's choosing.
var notices = map[string]string{
	"user-created":         "User created.",
	"unlocked":             "The account is unlocked.",
	"signed-out-user":      "The user is signed out everywhere.",
	"password-set":         "Password set. The user is signed out everywhere.",
	"reset-sent":           "A password reset email is on its way.",
	"verification-sent":    "A verification email is on its way.",
	"account-unlinked":     "The linked account was removed.",
	"session-revoked":      "The session was ended.",
	"2fa-reset":            "Two-factor authentication was reset.",
	"passkey-deleted":      "The passkey was removed.",
	"app-revoked":          "The application was disconnected.",
	"org-created":          "Organization created.",
	"org-deleted":          "The organization was deleted.",
	"org-suspended":        "The organization is suspended.",
	"org-restored":         "The organization is active again.",
	"owner-changed":        "Ownership transferred.",
	"member-added":         "Member added.",
	"member-removed":       "Member removed.",
	"invitation-sent":      "Invitation sent.",
	"invitation-cancelled": "Invitation cancelled.",
	"role-saved":           "Role saved.",
	"client-saved":         "Application saved.",
	"client-deleted":       "Application deleted.",
	"signed-out":           "You are signed out.",
	"saved":                "Changes saved.",
	"user-deleted":         "The user was deleted.",
	"roles-saved":          "Roles updated.",
	"role-created":         "Role created.",
	"role-deleted":         "Role deleted.",
	"audit-cleaned":        "Events older than the retention period were deleted.",
}

// render writes a whole page, or only the named fragment when htmx asked
// for that fragment by its target.
func (m *UIModule) render(w http.ResponseWriter, r *http.Request, status int, page string, data *view, fragments ...string) {
	tmpl, ok := m.pages.pages[page]
	if !ok {
		http.Error(w, "page not found", http.StatusInternalServerError)
		return
	}
	name := "layout"
	if target := r.Header.Get("HX-Target"); target != "" && r.Header.Get("HX-Boosted") != "true" {
		for _, fragment := range fragments {
			if fragment == target {
				name = fragment
			}
		}
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		m.deps.Logger.Error("ui: failed to render page", "page", page, "error", err)
		http.Error(w, "the page could not be rendered", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderError shows a full error page.
func (m *UIModule) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	data := m.newView(r, http.StatusText(status), "", map[string]any{"Status": status, "Message": message})
	m.render(w, r, status, "error", data)
}

func (m *UIModule) funcs() template.FuncMap {
	return template.FuncMap{
		"date": func(t any) string {
			switch value := t.(type) {
			case time.Time:
				if value.IsZero() {
					return "—"
				}
				return value.UTC().Format("2 Jan 2006, 15:04 UTC")
			case *time.Time:
				if value == nil || value.IsZero() {
					return "—"
				}
				return value.UTC().Format("2 Jan 2006, 15:04 UTC")
			}
			return "—"
		},
		"ago": func(t any) string {
			var value time.Time
			switch typed := t.(type) {
			case time.Time:
				value = typed
			case *time.Time:
				if typed == nil {
					return "never"
				}
				value = *typed
			}
			if value.IsZero() {
				return "never"
			}
			return ago(time.Since(value))
		},
		"initials": initials,
		"duration": humanDuration,
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"contains": func(list []string, value string) bool {
			for _, item := range list {
				if item == value {
					return true
				}
			}
			return false
		},
		"severity": func(severity string) string {
			switch severity {
			case "critical":
				return "danger"
			case "warning":
				return "warn"
			default:
				return "neutral"
			}
		},
	}
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute") + " ago"
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	case d < 30*24*time.Hour:
		return plural(int(d.Hours()/24), "day") + " ago"
	case d < 365*24*time.Hour:
		return plural(int(d.Hours()/24/30), "month") + " ago"
	default:
		return plural(int(d.Hours()/24/365), "year") + " ago"
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// initials returns up to two letters for an avatar.
func initials(name, email string) string {
	source := strings.TrimSpace(name)
	if source == "" {
		source = strings.TrimSpace(email)
	}
	var out []rune
	for _, word := range strings.FieldsFunc(source, func(r rune) bool { return r == ' ' || r == '.' || r == '_' || r == '-' || r == '@' }) {
		for _, r := range word {
			out = append(out, r)
			break
		}
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return strings.ToUpper(string(out))
}

// pager describes one page of a list.
type pager struct {
	Offset, Limit int
	Total         int64
	Path          string
	Query         string // the list's other query parameters, encoded
	Target        string
}

func (p pager) From() int64 {
	if p.Total == 0 {
		return 0
	}
	return int64(p.Offset) + 1
}

func (p pager) To() int64 {
	return min(int64(p.Offset+p.Limit), p.Total)
}

func (p pager) HasPrev() bool { return p.Offset > 0 }
func (p pager) HasNext() bool { return int64(p.Offset+p.Limit) < p.Total }

func (p pager) link(offset int) string {
	sep := "?"
	link := p.Path
	if p.Query != "" {
		link += sep + p.Query
		sep = "&"
	}
	if offset > 0 {
		link += fmt.Sprintf("%soffset=%d", sep, offset)
	}
	return link
}

func (p pager) PrevLink() string { return p.link(max(p.Offset-p.Limit, 0)) }
func (p pager) NextLink() string { return p.link(p.Offset + p.Limit) }

// timeNow is time.Now, replaceable in tests.
var timeNow = time.Now

// humanDuration writes a configured lifetime the way people say it:
// "15 minutes", "7 days", "1 hour 30 minutes".
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "not set"
	}
	units := []struct {
		size time.Duration
		name string
	}{{24 * time.Hour, "day"}, {time.Hour, "hour"}, {time.Minute, "minute"}, {time.Second, "second"}}
	var parts []string
	for _, unit := range units {
		if n := int(d / unit.size); n > 0 {
			parts = append(parts, plural(n, unit.name))
			d -= time.Duration(n) * unit.size
		}
		if len(parts) == 2 {
			break
		}
	}
	return strings.Join(parts, " ")
}
