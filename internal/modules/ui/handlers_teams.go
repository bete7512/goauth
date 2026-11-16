package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	orgservices "github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/team"
	teamservices "github.com/bete7512/goauth/internal/modules/team/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Teams live inside organizations, so their pages are an organization tab;
// the Teams entry of the sidebar lists the organizations to pick from. Every
// change goes through the team module's service as a super admin.

func (m *UIModule) teamService() teamservices.TeamService {
	module, ok := lookup[*team.TeamModule](m, types.TeamModule)
	if !ok {
		return nil
	}
	return team.ServiceOf(module)
}

func (m *UIModule) teamActor(r *http.Request) *teamservices.Actor {
	v := visitorFrom(r.Context())
	return &teamservices.Actor{UserID: v.User.ID, SuperAdmin: v.admin()}
}

// teamsAvailable answers with a page when the team module is missing.
func (m *UIModule) teamsAvailable(w http.ResponseWriter, r *http.Request) (teamservices.TeamService, bool) {
	service := m.teamService()
	if service == nil {
		m.unavailable(w, r, "Teams", "team")
		return nil, false
	}
	return service, true
}

// --- the sidebar's Teams page: organizations with their team counts ---

type teamsIndexPage struct {
	Query string
	Orgs  []teamsIndexRow
	Pager pager
}

type teamsIndexRow struct {
	Org   *models.Organization
	Teams int64
}

func (m *UIModule) teamsIndex(w http.ResponseWriter, r *http.Request) {
	service, ok := m.teamsAvailable(w, r)
	if !ok {
		return
	}
	orgs, ok := m.orgService(w, r)
	if !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.OrganizationListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "name", SortDir: "asc"}, Query: query}
	opts.Normalize(m.config.PageSize)
	list, total, authErr := orgs.ListOrganizations(r.Context(), opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &teamsIndexPage{Query: query}
	count := models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: 1}}
	count.Normalize(1)
	for _, org := range list {
		row := teamsIndexRow{Org: org}
		if _, n, authErr := service.List(r.Context(), m.teamActor(r), org.ID, count); authErr == nil {
			row.Teams = n
		}
		page.Orgs = append(page.Orgs, row)
	}
	params := url.Values{}
	if query != "" {
		params.Set("q", query)
	}
	page.Pager = pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.base + "/teams", Query: params.Encode(), Target: "teams-orgs"}
	m.render(w, r, http.StatusOK, "teams", m.newView(r, "Teams", "teams", page), "teams-orgs")
}

// --- an organization's teams ---

type orgTeamsPage struct {
	orgFrame
	Teams []*models.Team
	Form  teamservices.TeamInput
}

func (m *UIModule) orgTeams(w http.ResponseWriter, r *http.Request) {
	m.showOrgTeams(w, r, http.StatusOK, teamservices.TeamInput{ParentID: r.URL.Query().Get("parent")}, "")
}

func (m *UIModule) showOrgTeams(w http.ResponseWriter, r *http.Request, status int, form teamservices.TeamInput, message string) {
	service, ok := m.teamsAvailable(w, r)
	if !ok {
		return
	}
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	teams, authErr := service.Tree(r.Context(), m.teamActor(r), org.ID)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &orgTeamsPage{orgFrame: m.orgFrame(r, orgs, org, "teams"), Teams: teams, Form: form}
	data := m.newView(r, org.Name, "teams", page)
	data.Error = message
	m.render(w, r, status, "org_teams", data)
}

func (m *UIModule) createTeam(w http.ResponseWriter, r *http.Request) {
	service, ok := m.teamsAvailable(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	orgID := r.PathValue("orgId")
	input := teamservices.TeamInput{Name: r.PostForm.Get("name"), Slug: r.PostForm.Get("slug"), Description: r.PostForm.Get("description"), ParentID: r.PostForm.Get("parent_id")}
	created, authErr := service.Create(r.Context(), m.teamActor(r), orgID, input)
	if authErr != nil {
		m.showOrgTeams(w, r, statusFor(authErr), input, authErr.Message)
		return
	}
	m.redirect(w, r, m.teamURL(orgID, created.ID, "")+"?notice=team-created")
}

// --- one team ---

type teamPage struct {
	orgFrame
	Team      *models.Team
	Ancestors []*models.Team
	// Parents are the teams the team may move beneath: every team outside
	// its own sub-tree.
	Parents     []*models.Team
	Children    []*models.Team
	TeamMembers []teamMemberRow
	// OrgMembers are the organization's members not yet in the team, for
	// the add form.
	OrgMembers []orgservices.AdminMember
	TeamRoles  bool
}

type teamMemberRow struct {
	Member *models.TeamMember
	User   *models.User
}

func (m *UIModule) teamPage(w http.ResponseWriter, r *http.Request) {
	m.showTeam(w, r, http.StatusOK, "")
}

func (m *UIModule) showTeam(w http.ResponseWriter, r *http.Request, status int, message string) {
	service, ok := m.teamsAvailable(w, r)
	if !ok {
		return
	}
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	actor := m.teamActor(r)
	current, authErr := service.Get(r.Context(), actor, org.ID, r.PathValue("teamId"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	tree, authErr := service.Tree(r.Context(), actor, org.ID)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &teamPage{orgFrame: m.orgFrame(r, orgs, org, "teams"), Team: current}
	byID := map[string]*models.Team{}
	for _, t := range tree {
		byID[t.ID] = t
	}
	for _, id := range current.AncestorIDs() {
		if ancestor, ok := byID[id]; ok && id != current.ID {
			page.Ancestors = append(page.Ancestors, ancestor)
		}
	}
	for _, t := range tree {
		if t.ParentID == current.ID {
			page.Children = append(page.Children, t)
		}
		if !strings.HasPrefix(t.Path, current.Path) {
			page.Parents = append(page.Parents, t)
		}
	}
	opts := models.TeamMemberListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "role", SortDir: "asc"}}
	opts.Normalize(100)
	members, _, authErr := service.ListMembers(r.Context(), actor, org.ID, current.ID, opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	inTeam := map[string]bool{}
	for _, member := range members {
		row := teamMemberRow{Member: member}
		if user, err := m.deps.Storage.Core().Users().FindByID(r.Context(), member.UserID); err == nil {
			row.User = user
		}
		page.TeamMembers = append(page.TeamMembers, row)
		inTeam[member.UserID] = true
	}
	memberOpts := models.MemberListOpts{ListingOpts: models.ListingOpts{Limit: 100}}
	memberOpts.Normalize(100)
	if orgMembers, _, authErr := orgs.ListMembers(r.Context(), org.ID, memberOpts); authErr == nil {
		for _, member := range orgMembers {
			if !inTeam[member.Member.UserID] {
				page.OrgMembers = append(page.OrgMembers, member)
			}
		}
	}
	_, internals, enabled := m.rbacModule()
	page.TeamRoles = enabled && internals.Teams
	data := m.newView(r, current.Name, "teams", page)
	data.Error = message
	m.render(w, r, status, "team", data)
}

func (m *UIModule) teamAction(w http.ResponseWriter, r *http.Request, notice string, action func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError)) {
	service, ok := m.teamsAvailable(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	orgID, teamID := r.PathValue("orgId"), r.PathValue("teamId")
	target, authErr := action(service, m.teamActor(r), orgID, teamID)
	if authErr != nil {
		m.showTeam(w, r, statusFor(authErr), authErr.Message)
		return
	}
	if target == "" {
		target = m.teamURL(orgID, teamID, "")
	}
	m.redirect(w, r, target+"?notice="+notice)
}

func (m *UIModule) updateTeam(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "saved", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		_, authErr := service.Update(r.Context(), actor, orgID, teamID, teamservices.TeamInput{Name: r.PostForm.Get("name"), Slug: r.PostForm.Get("slug"), Description: r.PostForm.Get("description")})
		return "", authErr
	})
}

func (m *UIModule) moveTeam(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "team-moved", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		_, authErr := service.Move(r.Context(), actor, orgID, teamID, r.PostForm.Get("parent_id"))
		return "", authErr
	})
}

func (m *UIModule) deleteTeam(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "team-deleted", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		return m.orgURL(orgID, "teams"), service.Delete(r.Context(), actor, orgID, teamID)
	})
}

func (m *UIModule) addTeamMember(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "member-added", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		_, authErr := service.AddMember(r.Context(), actor, orgID, teamID, r.PostForm.Get("user_id"), r.PostForm.Get("role"))
		return "", authErr
	})
}

func (m *UIModule) changeTeamMemberRole(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "saved", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		return "", service.ChangeMemberRole(r.Context(), actor, orgID, teamID, r.PathValue("userId"), r.PostForm.Get("role"))
	})
}

func (m *UIModule) removeTeamMember(w http.ResponseWriter, r *http.Request) {
	m.teamAction(w, r, "member-removed", func(service teamservices.TeamService, actor *teamservices.Actor, orgID, teamID string) (string, *types.GoAuthError) {
		return "", service.RemoveMember(r.Context(), actor, orgID, teamID, r.PathValue("userId"))
	})
}

// --- a member's roles inside a team ---

type teamMemberPage struct {
	orgFrame
	Team  *models.Team
	User  *models.User
	Role  string
	Roles *rbacRoles
}

func (m *UIModule) teamMember(w http.ResponseWriter, r *http.Request) {
	m.showTeamMember(w, r, http.StatusOK, "")
}

func (m *UIModule) showTeamMember(w http.ResponseWriter, r *http.Request, status int, message string) {
	service, ok := m.teamsAvailable(w, r)
	if !ok {
		return
	}
	orgs, org, ok := m.loadOrg(w, r)
	if !ok {
		return
	}
	current, authErr := service.Get(r.Context(), m.teamActor(r), org.ID, r.PathValue("teamId"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	userID := r.PathValue("userId")
	page := &teamMemberPage{orgFrame: m.orgFrame(r, orgs, org, "teams"), Team: current}
	if user, err := m.deps.Storage.Core().Users().FindByID(r.Context(), userID); err == nil {
		page.User = user
	}
	if page.User == nil {
		m.renderError(w, r, http.StatusNotFound, "This user does not exist.")
		return
	}
	if memberships, authErr := service.UserTeams(r.Context(), m.teamActor(r), org.ID, userID); authErr == nil {
		for _, membership := range memberships {
			if membership.TeamID == current.ID {
				page.Role = membership.Role
			}
		}
	}
	if _, internals, enabled := m.rbacModule(); enabled && internals.Teams {
		scope := access.TeamScope(current.ID)
		scope.Org = org.ID
		page.Roles = m.heldRoles(r, internals, userID, scope)
		page.Roles.Action = m.teamURL(org.ID, current.ID, "members/"+url.PathEscape(userID)+"/roles")
	}
	data := m.newView(r, current.Name, "teams", page)
	data.Error = message
	m.render(w, r, status, "team_member", data)
}

func (m *UIModule) setTeamMemberRoles(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	_, internals, enabled := m.rbacModule()
	if !enabled || !internals.Teams {
		m.unavailable(w, r, "Team roles", "rbac (with Teams: true)")
		return
	}
	orgID, teamID, userID := r.PathValue("orgId"), r.PathValue("teamId"), r.PathValue("userId")
	scope := access.TeamScope(teamID)
	scope.Org = orgID
	if _, authErr := internals.Assignments.Set(r.Context(), m.actor(r), userID, scope, r.PostForm["roles"]); authErr != nil {
		m.showTeamMember(w, r, http.StatusUnprocessableEntity, authErr.Message)
		return
	}
	m.redirect(w, r, m.teamURL(orgID, teamID, "members/"+url.PathEscape(userID))+"?notice=roles-saved")
}

func (m *UIModule) teamURL(orgID, teamID, rest string) string {
	link := m.orgURL(orgID, "teams/"+url.PathEscape(teamID))
	if rest != "" {
		link += "/" + rest
	}
	return link
}
