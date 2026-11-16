package ui

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	orgservices "github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

const orgsTable = "orgs-table"

// orgService returns the organization admin service, or answers that the
// module is not registered.
func (m *UIModule) orgService(w http.ResponseWriter, r *http.Request) (orgservices.AdminService, bool) {
	orgs := m.orgAdmin()
	if orgs == nil {
		m.unavailable(w, r, "Organizations", "organization")
		return nil, false
	}
	return orgs, true
}

// --- list and create ---

type orgsPage struct {
	Query string
	Orgs  []*models.Organization
	Pager pager
}

func (m *UIModule) orgs(w http.ResponseWriter, r *http.Request) {
	orgs, ok := m.orgService(w, r)
	if !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.OrganizationListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}, Query: query}
	opts.Normalize(m.config.PageSize)
	list, total, authErr := orgs.ListOrganizations(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	params := url.Values{}
	if query != "" {
		params.Set("q", query)
	}
	page := &orgsPage{Query: query, Orgs: list, Pager: pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/orgs", Query: params.Encode(), Target: orgsTable}}
	m.render(w, r, http.StatusOK, "orgs", m.newView(r, "Organizations", "orgs", page), orgsTable)
}

type newOrgPage struct {
	Name, Slug, OwnerEmail string
}

func (m *UIModule) newOrgPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.orgService(w, r); !ok {
		return
	}
	m.render(w, r, http.StatusOK, "org_new", m.newView(r, "New organization", "orgs", &newOrgPage{OwnerEmail: r.URL.Query().Get("owner")}))
}

func (m *UIModule) createOrg(w http.ResponseWriter, r *http.Request) {
	orgs, ok := m.orgService(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	page := &newOrgPage{Name: strings.TrimSpace(r.PostForm.Get("name")), Slug: strings.TrimSpace(r.PostForm.Get("slug")), OwnerEmail: strings.TrimSpace(r.PostForm.Get("owner_email"))}
	org, authErr := orgs.CreateOrganization(r.Context(), page.OwnerEmail, page.Name, page.Slug)
	if authErr != nil {
		data := m.newView(r, "New organization", "orgs", page)
		data.Error = orgMessage(authErr)
		m.render(w, r, http.StatusUnprocessableEntity, "org_new", data)
		return
	}
	m.redirect(w, r, m.orgURL(org.ID, "")+"?notice=org-created")
}

// --- one organization ---

type orgFrame struct {
	Base    string // the console root, for links
	Org     *models.Organization
	Owner   *models.User
	Members int64
	Tabs    []tab
}

func (m *UIModule) orgFrame(r *http.Request, orgs orgservices.AdminService, org *models.Organization, current string) orgFrame {
	base := m.orgURL(org.ID, "")
	frame := orgFrame{Base: m.base, Org: org}
	if owner, err := m.deps.Storage.Core().Users().FindByID(r.Context(), org.OwnerID); err == nil {
		frame.Owner = owner
	}
	opts := models.MemberListOpts{ListingOpts: models.ListingOpts{Limit: 1}}
	opts.Normalize(1)
	if _, total, authErr := orgs.ListMembers(r.Context(), org.ID, opts); authErr == nil {
		frame.Members = total
	}
	frame.Tabs = []tab{
		{Label: "Overview", Href: base, Current: current == "overview"},
		{Label: "Members", Href: base + "/members", Current: current == "members", Count: int(frame.Members)},
		{Label: "Invitations", Href: base + "/invitations", Current: current == "invitations"},
	}
	if m.features().Teams {
		frame.Tabs = append(frame.Tabs, tab{Label: "Teams", Href: base + "/teams", Current: current == "teams"})
	}
	if m.features().OrgRoles {
		frame.Tabs = append(frame.Tabs, tab{Label: "Roles", Href: base + "/roles", Current: current == "roles"})
	}
	return frame
}

func (m *UIModule) loadOrg(w http.ResponseWriter, r *http.Request) (orgservices.AdminService, *models.Organization, bool) {
	orgs, ok := m.orgService(w, r)
	if !ok {
		return nil, nil, false
	}
	org, authErr := orgs.GetOrganization(r.Context(), r.PathValue("orgId"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return nil, nil, false
	}
	return orgs, org, true
}

type orgPage struct {
	orgFrame
	Admins []orgservices.AdminMember // members who could become owner
}

func (m *UIModule) org(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	m.showOrg(w, r, http.StatusOK, orgs, org, "")
}

func (m *UIModule) showOrg(w http.ResponseWriter, r *http.Request, status int, orgs orgservices.AdminService, org *models.Organization, message string) {
	page := &orgPage{orgFrame: m.orgFrame(r, orgs, org, "overview")}
	opts := models.MemberListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "joined_at", SortDir: "asc"}}
	opts.Normalize(100)
	if members, _, authErr := orgs.ListMembers(r.Context(), org.ID, opts); authErr == nil {
		for _, member := range members {
			if member.User != nil && member.Member.UserID != org.OwnerID {
				page.Admins = append(page.Admins, member)
			}
		}
	}
	data := m.newView(r, org.Name, "orgs", page)
	data.Error = message
	m.render(w, r, status, "org", data)
}

// orgAction runs an action on the organization in the path and redirects,
// or shows the error on the overview.
func (m *UIModule) orgAction(w http.ResponseWriter, r *http.Request, next func(org *models.Organization) string, action func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	if authErr := action(r.Context(), orgs, org); authErr != nil {
		m.showOrg(w, r, statusFor(authErr), orgs, org, orgMessage(authErr))
		return
	}
	m.redirect(w, r, next(org))
}

func (m *UIModule) updateOrg(w http.ResponseWriter, r *http.Request) {
	m.orgAction(w, r, func(org *models.Organization) string { return m.orgURL(org.ID, "") + "?notice=saved" },
		func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
			_, authErr := orgs.UpdateOrganization(ctx, org.ID, r.PostForm.Get("name"), r.PostForm.Get("logo_url"))
			return authErr
		})
}

func (m *UIModule) setOrgStatus(w http.ResponseWriter, r *http.Request) {
	active := r.FormValue("active") == "true"
	notice := "org-suspended"
	if active {
		notice = "org-restored"
	}
	m.orgAction(w, r, func(org *models.Organization) string { return m.orgURL(org.ID, "") + "?notice=" + notice },
		func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
			return orgs.SetActive(ctx, org.ID, active)
		})
}

func (m *UIModule) deleteOrg(w http.ResponseWriter, r *http.Request) {
	m.orgAction(w, r, func(*models.Organization) string { return m.base + "/orgs?notice=org-deleted" },
		func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
			if r.PostForm.Get("confirm") != org.Slug {
				return types.NewValidationError("Type the organization's slug to confirm.")
			}
			return orgs.DeleteOrganization(ctx, org.ID)
		})
}

func (m *UIModule) transferOrg(w http.ResponseWriter, r *http.Request) {
	m.orgAction(w, r, func(org *models.Organization) string { return m.orgURL(org.ID, "") + "?notice=owner-changed" },
		func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
			return orgs.TransferOwnership(ctx, org.ID, r.PostForm.Get("user_id"))
		})
}

// --- members ---

type orgMembersPage struct {
	orgFrame
	List     []orgservices.AdminMember
	Pager    pager
	OrgRoles bool
}

func (m *UIModule) orgMembers(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	m.showOrgMembers(w, r, http.StatusOK, orgs, org, "")
}

func (m *UIModule) showOrgMembers(w http.ResponseWriter, r *http.Request, status int, orgs orgservices.AdminService, org *models.Organization, message string) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.MemberListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "joined_at", SortDir: "asc"}}
	opts.Normalize(m.config.PageSize)
	members, total, authErr := orgs.ListMembers(r.Context(), org.ID, opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &orgMembersPage{orgFrame: m.orgFrame(r, orgs, org, "members"), List: members, OrgRoles: m.features().OrgRoles,
		Pager: pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.orgURL(org.ID, "members"), Target: "members-table"}}
	data := m.newView(r, org.Name, "orgs", page)
	data.Error = message
	m.render(w, r, status, "org_members", data, "members-table")
}

// memberAction runs an action on a member and returns to the members tab.
func (m *UIModule) memberAction(w http.ResponseWriter, r *http.Request, notice string, action func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	if authErr := action(r.Context(), orgs, org); authErr != nil {
		m.showOrgMembers(w, r, statusFor(authErr), orgs, org, orgMessage(authErr))
		return
	}
	m.redirect(w, r, m.orgURL(org.ID, "members")+"?notice="+notice)
}

func (m *UIModule) addOrgMember(w http.ResponseWriter, r *http.Request) {
	m.memberAction(w, r, "member-added", func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
		return orgs.AddMember(ctx, org.ID, r.PostForm.Get("email"), types.OrgRole(r.PostForm.Get("role")))
	})
}

func (m *UIModule) changeOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	m.memberAction(w, r, "saved", func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
		return orgs.ChangeMemberRole(ctx, org.ID, r.PathValue("userId"), types.OrgRole(r.PostForm.Get("role")))
	})
}

func (m *UIModule) removeOrgMember(w http.ResponseWriter, r *http.Request) {
	m.memberAction(w, r, "member-removed", func(ctx context.Context, orgs orgservices.AdminService, org *models.Organization) *types.GoAuthError {
		return orgs.RemoveMember(ctx, org.ID, r.PathValue("userId"))
	})
}

// --- one member's roles ---

type orgMemberPage struct {
	orgFrame
	Member orgservices.AdminMember
	Roles  *rbacRoles
}

func (m *UIModule) orgMember(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	m.showOrgMember(w, r, http.StatusOK, orgs, org, "")
}

func (m *UIModule) showOrgMember(w http.ResponseWriter, r *http.Request, status int, orgs orgservices.AdminService, org *models.Organization, message string) {
	userID := r.PathValue("userId")
	member, found := m.findMember(r, orgs, org.ID, userID)
	if !found {
		m.renderError(w, r, http.StatusNotFound, "This user is not a member of the organization.")
		return
	}
	page := &orgMemberPage{orgFrame: m.orgFrame(r, orgs, org, "members"), Member: member}
	if _, internals, ok := m.rbacModule(); ok && internals.Organizations {
		page.Roles = m.heldRoles(r, internals, userID, access.OrgScope(org.ID))
		page.Roles.Action = m.orgURL(org.ID, "members/"+url.PathEscape(userID)+"/roles")
	}
	data := m.newView(r, org.Name, "orgs", page)
	data.Error = message
	m.render(w, r, status, "org_member", data)
}

func (m *UIModule) findMember(r *http.Request, orgs orgservices.AdminService, orgID, userID string) (orgservices.AdminMember, bool) {
	opts := models.MemberListOpts{ListingOpts: models.ListingOpts{Limit: 100}}
	opts.Normalize(100)
	for offset := 0; ; offset += 100 {
		opts.Offset = offset
		members, total, authErr := orgs.ListMembers(r.Context(), orgID, opts)
		if authErr != nil {
			return orgservices.AdminMember{}, false
		}
		for _, member := range members {
			if member.Member.UserID == userID {
				return member, true
			}
		}
		if int64(offset+100) >= total {
			return orgservices.AdminMember{}, false
		}
	}
}

func (m *UIModule) setOrgMemberRoles(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	_, internals, enabled := m.rbacModule()
	if !enabled || !internals.Organizations {
		m.unavailable(w, r, "Organization roles", "rbac (with Organizations: true)")
		return
	}
	userID := r.PathValue("userId")
	if _, authErr := internals.Assignments.Set(r.Context(), m.actor(r), userID, access.OrgScope(org.ID), r.PostForm["roles"]); authErr != nil {
		m.showOrgMember(w, r, http.StatusUnprocessableEntity, orgs, org, authErr.Message)
		return
	}
	m.redirect(w, r, m.orgURL(org.ID, "members/"+url.PathEscape(userID))+"?notice=roles-saved")
}

// --- invitations ---

type orgInvitationsPage struct {
	orgFrame
	Invitations []*models.OrgInvitation
	Pager       pager
	Email, Role string // the send form, kept after an error
}

func (m *UIModule) orgInvitations(w http.ResponseWriter, r *http.Request) {
	m.showOrgInvitations(w, r, http.StatusOK, "", "member", "")
}

func (m *UIModule) showOrgInvitations(w http.ResponseWriter, r *http.Request, status int, email, role, message string) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.OrgInvitationListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}}
	opts.Normalize(m.config.PageSize)
	invitations, total, authErr := orgs.ListInvitations(r.Context(), org.ID, opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &orgInvitationsPage{orgFrame: m.orgFrame(r, orgs, org, "invitations"), Invitations: invitations, Email: email, Role: role,
		Pager: pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.orgURL(org.ID, "invitations"), Target: "invitations-table"}}
	data := m.newView(r, org.Name, "orgs", page)
	data.Error = message
	m.render(w, r, status, "org_invitations", data, "invitations-table")
}

// sendOrgInvitation invites someone to the organization as a super admin.
func (m *UIModule) sendOrgInvitation(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	email, role := strings.TrimSpace(r.PostForm.Get("email")), r.PostForm.Get("role")
	if _, authErr := orgs.InviteMember(r.Context(), org.ID, email, role); authErr != nil {
		m.showOrgInvitations(w, r, statusFor(authErr), email, role, orgMessage(authErr))
		return
	}
	m.redirect(w, r, m.orgURL(org.ID, "invitations")+"?notice=invitation-sent")
}

// importOrgInvitations invites every address of a list: email[,role],
// where the role is admin or member.
func (m *UIModule) importOrgInvitations(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	source, err := importSource(w, r)
	if err != nil {
		m.showOrgInvitations(w, r, http.StatusUnprocessableEntity, "", "member", err.Error())
		return
	}
	defaultRole := r.FormValue("role")
	if defaultRole == "" {
		defaultRole = "member"
	}
	rows, err := parseImport(source, defaultRole)
	if err != nil {
		m.showOrgInvitations(w, r, http.StatusUnprocessableEntity, "", "member", err.Error())
		return
	}
	page := &importPage{Rows: rows, Back: m.orgURL(org.ID, "invitations"), BackLabel: org.Name + " invitations", Column: "Role"}
	for i := range page.Rows {
		row := &page.Rows[i]
		if row.Problem == "" {
			if _, authErr := orgs.InviteMember(r.Context(), org.ID, row.Email, strings.ToLower(row.Purpose)); authErr != nil {
				row.Problem = orgMessage(authErr)
			} else {
				row.Sent = true
			}
		}
		if row.Sent {
			page.Sent++
		} else {
			page.Skipped++
		}
	}
	m.render(w, r, http.StatusOK, "invitations_import", m.newView(r, "Invitation import", "orgs", page))
}

func (m *UIModule) cancelOrgInvitation(w http.ResponseWriter, r *http.Request) {
	orgs, org, ok := m.loadOrg(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	if authErr := orgs.CancelInvitation(r.Context(), org.ID, r.PathValue("invId")); authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	m.redirect(w, r, m.orgURL(org.ID, "invitations")+"?notice=invitation-cancelled")
}

// --- helpers ---

func (m *UIModule) orgURL(orgID, tab string) string {
	link := m.base + "/orgs/" + url.PathEscape(orgID)
	if tab != "" {
		link += "/" + tab
	}
	return link
}

// orgMessage words organization errors for the console.
func orgMessage(authErr *types.GoAuthError) string {
	switch authErr.Code {
	case types.ErrOrgCannotRemoveOwner:
		return "The owner cannot be removed or demoted. Transfer ownership first."
	case types.ErrUserNotFound:
		return "No user has that email address."
	case types.ErrOrgMemberExists:
		return "That user is already a member."
	}
	if authErr.StatusCode >= http.StatusInternalServerError {
		return "Something went wrong. Try again."
	}
	return authErr.Message
}
