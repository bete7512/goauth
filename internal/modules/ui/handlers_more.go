package ui

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	idpdto "github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	invitationdto "github.com/bete7512/goauth/internal/modules/invitation/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// splitGrants reads one grant per line; commas also separate.
func splitGrants(text string) []string {
	var grants []string
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		if grant := strings.TrimSpace(field); grant != "" {
			grants = append(grants, grant)
		}
	}
	return grants
}

// splitLines reads one value per line, for redirect URIs and scopes.
func splitLines(text string) []string {
	var out []string
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ' ' || r == ',' }) {
		if value := strings.TrimSpace(field); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// --- platform invitations ---

type invitationsPage struct {
	Status      string
	Invitations []*models.Invitation
	Inviters    map[string]*models.User
	Pager       pager
	Email       string
	Purpose     string
}

func (m *UIModule) invitations(w http.ResponseWriter, r *http.Request) {
	m.showInvitations(w, r, http.StatusOK, &invitationsPage{}, "")
}

func (m *UIModule) showInvitations(w http.ResponseWriter, r *http.Request, status int, page *invitationsPage, message string) {
	service := m.invitationService()
	if service == nil {
		m.unavailable(w, r, "Invitations", "invitation")
		return
	}
	page.Status = strings.TrimSpace(r.URL.Query().Get("status"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.InvitationListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}, Status: page.Status}
	opts.Normalize(m.config.PageSize)
	list, total, authErr := service.AdminList(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page.Invitations = list
	page.Inviters = map[string]*models.User{}
	for _, invitation := range list {
		if _, seen := page.Inviters[invitation.InviterID]; !seen {
			user, _ := m.deps.Storage.Core().Users().FindByID(r.Context(), invitation.InviterID)
			page.Inviters[invitation.InviterID] = user
		}
	}
	params := url.Values{}
	if page.Status != "" {
		params.Set("status", page.Status)
	}
	page.Pager = pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/invitations", Query: params.Encode(), Target: "invitations-table"}
	data := m.newView(r, "Invitations", "invitations", page)
	data.Error = message
	m.render(w, r, status, "invitations", data, "invitations-table")
}

func (m *UIModule) sendInvitation(w http.ResponseWriter, r *http.Request) {
	service := m.invitationService()
	if service == nil {
		m.unavailable(w, r, "Invitations", "invitation")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	request := &invitationdto.SendInvitationRequest{Email: strings.TrimSpace(r.PostForm.Get("email")), Purpose: strings.TrimSpace(r.PostForm.Get("purpose"))}
	page := &invitationsPage{Email: request.Email, Purpose: request.Purpose}
	if err := request.Validate(); err != nil {
		m.showInvitations(w, r, http.StatusUnprocessableEntity, page, err.Error())
		return
	}
	if _, authErr := service.Send(r.Context(), request, visitorFrom(r.Context()).User.ID); authErr != nil {
		m.showInvitations(w, r, http.StatusUnprocessableEntity, page, authErr.Message)
		return
	}
	m.redirect(w, r, m.base+"/invitations?notice=invitation-sent")
}

func (m *UIModule) cancelInvitation(w http.ResponseWriter, r *http.Request) {
	service := m.invitationService()
	if service == nil {
		m.unavailable(w, r, "Invitations", "invitation")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	if authErr := service.AdminCancel(r.Context(), r.PathValue("invId")); authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	m.redirect(w, r, m.base+"/invitations?notice=invitation-cancelled")
}

// --- OIDC clients ---

type clientsPage struct {
	Query   string
	Clients []idpdto.Client
	Pager   pager
}

func (m *UIModule) clients(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.IDPClientListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}, Query: query}
	opts.Normalize(m.config.PageSize)
	list, total, authErr := idp.AdminListClients(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	params := url.Values{}
	if query != "" {
		params.Set("q", query)
	}
	page := &clientsPage{Query: query, Clients: list, Pager: pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/clients", Query: params.Encode(), Target: "clients-table"}}
	m.render(w, r, http.StatusOK, "clients", m.newView(r, "OIDC clients", "clients", page), "clients-table")
}

// clientForm is the create and edit form of a client.
type clientForm struct {
	ClientID     string
	Name         string
	RedirectURIs string
	Scopes       string
	Public       bool
	RequirePKCE  bool
	SkipConsent  bool
	LogoURI      string
	ClientURI    string
	Disabled     bool
}

func (f clientForm) request() *idpdto.ClientRequest {
	pkce := f.RequirePKCE
	return &idpdto.ClientRequest{
		ClientID: f.ClientID, Name: f.Name, RedirectURIs: splitLines(f.RedirectURIs), Scopes: splitLines(f.Scopes),
		Public: f.Public, RequirePKCE: &pkce, SkipConsent: f.SkipConsent, LogoURI: f.LogoURI, ClientURI: f.ClientURI, Disabled: f.Disabled,
	}
}

func readClientForm(r *http.Request) clientForm {
	form := r.PostForm
	return clientForm{
		ClientID:     strings.TrimSpace(form.Get("client_id")),
		Name:         strings.TrimSpace(form.Get("name")),
		RedirectURIs: form.Get("redirect_uris"),
		Scopes:       form.Get("scopes"),
		Public:       form.Get("public") == "on",
		RequirePKCE:  form.Get("require_pkce") == "on",
		SkipConsent:  form.Get("skip_consent") == "on",
		LogoURI:      strings.TrimSpace(form.Get("logo_uri")),
		ClientURI:    strings.TrimSpace(form.Get("client_uri")),
		Disabled:     form.Get("disabled") == "on",
	}
}

func formOf(client *idpdto.Client) clientForm {
	return clientForm{
		ClientID: client.ClientID, Name: client.Name, RedirectURIs: strings.Join(client.RedirectURIs, "\n"), Scopes: strings.Join(client.Scopes, " "),
		Public: client.Public, RequirePKCE: client.RequirePKCE, SkipConsent: client.SkipConsent, LogoURI: client.LogoURI, ClientURI: client.ClientURI, Disabled: client.Disabled,
	}
}

type clientPage struct {
	Client *idpdto.Client // nil on the create page
	Form   clientForm
	Secret string // shown once, after creating or rotating
	Issuer string
}

func (m *UIModule) issuer() string {
	return strings.TrimRight(m.deps.Config.APIURL, "/") + strings.TrimRight(m.deps.Config.BasePath, "/") + "/oidc"
}

func (m *UIModule) newClientPage(w http.ResponseWriter, r *http.Request) {
	if m.idpService() == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	page := &clientPage{Form: clientForm{RequirePKCE: true, Scopes: "openid profile email"}, Issuer: m.issuer()}
	m.render(w, r, http.StatusOK, "client", m.newView(r, "New OIDC client", "clients", page))
}

func (m *UIModule) createClient(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	form := readClientForm(r)
	client, authErr := idp.AdminCreateClient(r.Context(), visitorFrom(r.Context()).User.ID, form.request())
	if authErr != nil {
		data := m.newView(r, "New OIDC client", "clients", &clientPage{Form: form, Issuer: m.issuer()})
		data.Error = authErr.Message
		m.render(w, r, http.StatusUnprocessableEntity, "client", data)
		return
	}
	// The secret exists only in this response, so the page is rendered here
	// rather than after a redirect.
	page := &clientPage{Client: client, Form: formOf(client), Secret: client.ClientSecret, Issuer: m.issuer()}
	m.render(w, r, http.StatusCreated, "client", m.newView(r, client.Name, "clients", page))
}

func (m *UIModule) client(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	client, authErr := idp.AdminGetClient(r.Context(), r.PathValue("clientId"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &clientPage{Client: client, Form: formOf(client), Issuer: m.issuer()}
	m.render(w, r, http.StatusOK, "client", m.newView(r, client.Name, "clients", page))
}

func (m *UIModule) updateClient(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	id := r.PathValue("clientId")
	form := readClientForm(r)
	if _, authErr := idp.AdminUpdateClient(r.Context(), visitorFrom(r.Context()).User.ID, id, form.request()); authErr != nil {
		current, getErr := idp.AdminGetClient(r.Context(), id)
		if getErr != nil {
			m.serviceError(w, r, getErr)
			return
		}
		data := m.newView(r, current.Name, "clients", &clientPage{Client: current, Form: form, Issuer: m.issuer()})
		data.Error = authErr.Message
		m.render(w, r, http.StatusUnprocessableEntity, "client", data)
		return
	}
	m.redirect(w, r, m.base+"/clients/"+url.PathEscape(id)+"?notice=client-saved")
}

func (m *UIModule) rotateClient(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	client, authErr := idp.AdminRotateClientSecret(r.Context(), visitorFrom(r.Context()).User.ID, r.PathValue("clientId"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &clientPage{Client: client, Form: formOf(client), Secret: client.ClientSecret, Issuer: m.issuer()}
	m.render(w, r, http.StatusOK, "client", m.newView(r, client.Name, "clients", page))
}

func (m *UIModule) deleteClient(w http.ResponseWriter, r *http.Request) {
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "OIDC clients", "idp (identity provider)")
		return
	}
	if !parseForm(w, r, m) {
		return
	}
	if authErr := idp.AdminDeleteClient(r.Context(), visitorFrom(r.Context()).User.ID, r.PathValue("clientId")); authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	m.redirect(w, r, m.base+"/clients?notice=client-deleted")
}

// --- settings ---

type moduleState struct {
	Name, Purpose string
	Enabled       bool
}

type settingsPage struct {
	Config  settingsView
	Modules []moduleState
}

type settingsView struct {
	Strategy, AuthMode, BasePath, Console, APIURL string
	Security                                      types.SecurityConfig
	SameSite                                      string
	RateLimit                                     string
	TrustedProxies                                []string
	RequireEmailVerification                      bool
	RequirePhoneVerification                      bool
}

var moduleCatalog = []moduleState{
	{Name: "core", Purpose: "Signup, profile, password and verification"},
	{Name: "stateless", Purpose: "JWT access and refresh tokens"},
	{Name: "session", Purpose: "Server-side sessions"},
	{Name: "notification", Purpose: "Email and SMS delivery"},
	{Name: "twofactor", Purpose: "TOTP and backup codes"},
	{Name: "passkeys", Purpose: "WebAuthn sign-in"},
	{Name: "oauth", Purpose: "Social sign-in"},
	{Name: "saml", Purpose: "Enterprise single sign-on"},
	{Name: "magiclink", Purpose: "Passwordless email sign-in"},
	{Name: "admin", Purpose: "User administration API"},
	{Name: "audit", Purpose: "Security event log"},
	{Name: "organization", Purpose: "Organizations and memberships"},
	{Name: "invitation", Purpose: "Platform invitations"},
	{Name: "rbac", Purpose: "Roles and permissions"},
	{Name: "idp", Purpose: "OpenID Connect provider"},
	{Name: "captcha", Purpose: "Bot protection on chosen routes"},
	{Name: "csrf", Purpose: "Double-submit CSRF protection"},
	{Name: "ratelimit", Purpose: "Request rate limiting"},
	{Name: "ui", Purpose: "This console"},
}

func (m *UIModule) settings(w http.ResponseWriter, r *http.Request) {
	cfg := m.deps.Config
	view := settingsView{
		Strategy: string(cfg.Security.AuthStrategy), AuthMode: string(cfg.Security.AuthMode), BasePath: cfg.BasePath,
		Console: m.base, APIURL: cfg.APIURL, Security: cfg.Security, TrustedProxies: cfg.TrustedProxies,
	}
	if view.AuthMode == "" {
		view.AuthMode = string(types.AuthModeBoth)
	}
	switch cfg.Security.Session.SameSite {
	case http.SameSiteStrictMode:
		view.SameSite = "Strict"
	case http.SameSiteNoneMode:
		view.SameSite = "None"
	default:
		view.SameSite = "Lax"
	}
	switch {
	case cfg.RateLimit != nil && cfg.RateLimit.Disabled:
		view.RateLimit = "Off"
	case cfg.RateLimit != nil && len(cfg.RateLimit.Rules) > 0:
		view.RateLimit = strconv.Itoa(len(cfg.RateLimit.Rules)) + " custom rules"
	default:
		view.RateLimit = "Default rules"
	}
	if cfg.Core != nil {
		view.RequireEmailVerification = cfg.Core.RequireEmailVerification
		view.RequirePhoneVerification = cfg.Core.RequirePhoneVerification
	}
	page := &settingsPage{Config: view}
	for _, module := range moduleCatalog {
		_, module.Enabled = m.deps.Lookup(module.Name)
		page.Modules = append(page.Modules, module)
	}
	sort.SliceStable(page.Modules, func(i, j int) bool { return page.Modules[i].Enabled && !page.Modules[j].Enabled })
	m.render(w, r, http.StatusOK, "settings", m.newView(r, "Settings", "settings", page))
}
