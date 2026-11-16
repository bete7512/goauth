// Package services holds the team module's business logic: nested teams
// inside organizations and who is in them.
package services

//go:generate mockgen -destination=../../../mocks/mock_team_service.go -package=mocks -mock_names=TeamService=MockTeamService github.com/bete7512/goauth/internal/modules/team/services TeamService

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Actor is who asks. A nil actor is the application's own code and skips
// every check; SuperAdmin is the platform administrator, who manages every
// team.
type Actor struct {
	UserID     string
	SuperAdmin bool
}

// TeamInput creates or edits a team. An empty Slug is made from Name.
type TeamInput struct {
	Name        string
	Slug        string
	Description string
	// ParentID places a new team beneath another; "" makes it top-level.
	ParentID string
}

// TeamService manages an organization's teams. Who may do what:
//
//   - Any member of the organization may read its teams and their members.
//   - The organization's owner and admins manage every team.
//   - A team's leads manage that team and every team beneath it: they add
//     and remove members, rename it and create teams under it.
//   - Deleting or moving a team needs the right to manage where it sits:
//     its parent, or for a top-level team the organization itself.
//
// These are ranks, like the organization module's member roles; permission
// checks for the application's own resources inside teams belong to rbac.
type TeamService interface {
	Create(ctx context.Context, actor *Actor, orgID string, input TeamInput) (*models.Team, *types.GoAuthError)
	Get(ctx context.Context, actor *Actor, orgID, teamID string) (*models.Team, *types.GoAuthError)
	List(ctx context.Context, actor *Actor, orgID string, opts models.TeamListOpts) ([]*models.Team, int64, *types.GoAuthError)
	// Tree returns every team of the organization ordered so that each team
	// follows its parent.
	Tree(ctx context.Context, actor *Actor, orgID string) ([]*models.Team, *types.GoAuthError)
	Update(ctx context.Context, actor *Actor, orgID, teamID string, input TeamInput) (*models.Team, *types.GoAuthError)
	// Move puts a team beneath parentID, or at the top with "".
	Move(ctx context.Context, actor *Actor, orgID, teamID, parentID string) (*models.Team, *types.GoAuthError)
	Delete(ctx context.Context, actor *Actor, orgID, teamID string) *types.GoAuthError

	ListMembers(ctx context.Context, actor *Actor, orgID, teamID string, opts models.TeamMemberListOpts) ([]*models.TeamMember, int64, *types.GoAuthError)
	AddMember(ctx context.Context, actor *Actor, orgID, teamID, userID, role string) (*models.TeamMember, *types.GoAuthError)
	ChangeMemberRole(ctx context.Context, actor *Actor, orgID, teamID, userID, role string) *types.GoAuthError
	RemoveMember(ctx context.Context, actor *Actor, orgID, teamID, userID string) *types.GoAuthError
	// UserTeams returns the teams a user is in within the organization.
	UserTeams(ctx context.Context, actor *Actor, orgID, userID string) ([]*models.TeamMember, *types.GoAuthError)

	// CanManage reports whether the actor manages the team: an
	// organization owner or admin, or a lead of the team or one above it.
	CanManage(ctx context.Context, actor *Actor, team *models.Team) (bool, *types.GoAuthError)

	// Housekeeping, run from event hooks.
	RemoveOrgMember(ctx context.Context, orgID, userID string) error
	RemoveOrganization(ctx context.Context, orgID string) error
	RemoveUser(ctx context.Context, userID string) error
}

// Stores are the repositories the service uses.
type Stores struct {
	Teams   types.TeamStorage
	Orgs    models.OrganizationRepository
	Members models.OrganizationMemberRepository
	Users   models.UserRepository
}

type teamService struct {
	deps   config.ModuleDependencies
	stores Stores
	// maxTeams bounds the teams of one organization, so a tree always fits
	// on one page and a sub-tree in one query.
	maxTeams int
}

// NewTeamService creates the team service.
func NewTeamService(deps config.ModuleDependencies, stores Stores, maxTeams int) *teamService {
	return &teamService{deps: deps, stores: stores, maxTeams: maxTeams}
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Slugify makes a slug from a name: lowercase letters and digits joined by
// single hyphens.
func Slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

func (s *teamService) validate(input *TeamInput) *types.GoAuthError {
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	input.Description = strings.TrimSpace(input.Description)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 255 {
		return types.NewValidationError("A team needs a name of at most 255 characters")
	}
	if input.Slug == "" {
		input.Slug = Slugify(input.Name)
	}
	if len(input.Slug) > 100 || !slugPattern.MatchString(input.Slug) {
		return types.NewValidationError("The slug may use lowercase letters, digits and single hyphens, at most 100 characters")
	}
	if utf8.RuneCountInString(input.Description) > 1000 {
		return types.NewValidationError("The description may be at most 1000 characters")
	}
	return nil
}

// --- reading ---

func (s *teamService) Get(ctx context.Context, actor *Actor, orgID, teamID string) (*models.Team, *types.GoAuthError) {
	if authErr := s.canRead(ctx, actor, orgID); authErr != nil {
		return nil, authErr
	}
	return s.team(ctx, orgID, teamID)
}

func (s *teamService) List(ctx context.Context, actor *Actor, orgID string, opts models.TeamListOpts) ([]*models.Team, int64, *types.GoAuthError) {
	if authErr := s.canRead(ctx, actor, orgID); authErr != nil {
		return nil, 0, authErr
	}
	teams, total, err := s.stores.Teams.Teams().List(ctx, orgID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list teams").Wrap(err)
	}
	return teams, total, nil
}

func (s *teamService) Tree(ctx context.Context, actor *Actor, orgID string) ([]*models.Team, *types.GoAuthError) {
	if authErr := s.canRead(ctx, actor, orgID); authErr != nil {
		return nil, authErr
	}
	opts := models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: s.maxTeams, SortField: "name", SortDir: "asc"}}
	opts.Normalize(s.maxTeams)
	teams, _, err := s.stores.Teams.Teams().List(ctx, orgID, opts)
	if err != nil {
		return nil, types.NewInternalError("failed to list teams").Wrap(err)
	}
	return TreeOrder(teams), nil
}

// TreeOrder orders teams so that each follows its parent, siblings by name.
func TreeOrder(teams []*models.Team) []*models.Team {
	children := map[string][]*models.Team{}
	ids := map[string]bool{}
	for _, team := range teams {
		ids[team.ID] = true
	}
	for _, team := range teams {
		parent := team.ParentID
		if !ids[parent] {
			parent = "" // an orphan, or a sub-tree's root, goes at the top
		}
		children[parent] = append(children[parent], team)
	}
	for _, list := range children {
		sort.SliceStable(list, func(i, j int) bool {
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
	}
	out := make([]*models.Team, 0, len(teams))
	var walk func(parent string)
	walk = func(parent string) {
		for _, team := range children[parent] {
			out = append(out, team)
			walk(team.ID)
		}
	}
	walk("")
	return out
}

func (s *teamService) ListMembers(ctx context.Context, actor *Actor, orgID, teamID string, opts models.TeamMemberListOpts) ([]*models.TeamMember, int64, *types.GoAuthError) {
	if authErr := s.canRead(ctx, actor, orgID); authErr != nil {
		return nil, 0, authErr
	}
	if _, authErr := s.team(ctx, orgID, teamID); authErr != nil {
		return nil, 0, authErr
	}
	members, total, err := s.stores.Teams.Members().ListByTeam(ctx, teamID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list team members").Wrap(err)
	}
	return members, total, nil
}

func (s *teamService) UserTeams(ctx context.Context, actor *Actor, orgID, userID string) ([]*models.TeamMember, *types.GoAuthError) {
	if actor == nil || actor.SuperAdmin || actor.UserID != userID {
		if authErr := s.canRead(ctx, actor, orgID); authErr != nil {
			return nil, authErr
		}
	}
	members, err := s.stores.Teams.Members().ListByUser(ctx, orgID, userID)
	if err != nil {
		return nil, types.NewInternalError("failed to list the user's teams").Wrap(err)
	}
	return members, nil
}

// --- changing teams ---

func (s *teamService) Create(ctx context.Context, actor *Actor, orgID string, input TeamInput) (*models.Team, *types.GoAuthError) {
	if authErr := s.validate(&input); authErr != nil {
		return nil, authErr
	}
	if _, authErr := s.organization(ctx, orgID); authErr != nil {
		return nil, authErr
	}
	team := &models.Team{OrgID: orgID, ParentID: strings.TrimSpace(input.ParentID), Name: input.Name, Slug: input.Slug, Description: input.Description}
	parentPath := ""
	if team.ParentID != "" {
		parent, authErr := s.team(ctx, orgID, team.ParentID)
		if authErr != nil {
			if authErr.Code == types.ErrTeamNotFound {
				return nil, types.NewTeamInvalidParentError("The parent team does not exist in this organization")
			}
			return nil, authErr
		}
		if authErr := s.mustManage(ctx, actor, parent); authErr != nil {
			return nil, authErr
		}
		if parent.Depth+1 >= models.MaxTeamDepth {
			return nil, types.NewTeamTooDeepError(models.MaxTeamDepth)
		}
		parentPath = parent.Path
		team.Depth = parent.Depth + 1
	} else if authErr := s.mustManageOrg(ctx, actor, orgID); authErr != nil {
		return nil, authErr
	}
	if authErr := s.roomForTeam(ctx, orgID); authErr != nil {
		return nil, authErr
	}
	team.ID = newID()
	team.Path = models.TeamPath(parentPath, team.ID)
	if err := s.stores.Teams.Teams().Create(ctx, team); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewTeamSlugTakenError()
		}
		return nil, types.NewInternalError("failed to create team").Wrap(err)
	}
	s.emit(ctx, types.EventTeamCreated, actor, team, "", "")
	return team, nil
}

func (s *teamService) Update(ctx context.Context, actor *Actor, orgID, teamID string, input TeamInput) (*models.Team, *types.GoAuthError) {
	if authErr := s.validate(&input); authErr != nil {
		return nil, authErr
	}
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return nil, authErr
	}
	if authErr := s.mustManage(ctx, actor, team); authErr != nil {
		return nil, authErr
	}
	team.Name, team.Slug, team.Description = input.Name, input.Slug, input.Description
	if err := s.stores.Teams.Teams().Update(ctx, team); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewTeamSlugTakenError()
		}
		return nil, types.NewInternalError("failed to update team").Wrap(err)
	}
	s.emit(ctx, types.EventTeamUpdated, actor, team, "", "")
	return team, nil
}

func (s *teamService) Move(ctx context.Context, actor *Actor, orgID, teamID, parentID string) (*models.Team, *types.GoAuthError) {
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return nil, authErr
	}
	parentID = strings.TrimSpace(parentID)
	if parentID == team.ParentID {
		return team, nil
	}
	if authErr := s.mustManageWhere(ctx, actor, team); authErr != nil {
		return nil, authErr
	}
	subtree, err := s.stores.Teams.Teams().Subtree(ctx, orgID, team.Path)
	if err != nil {
		return nil, types.NewInternalError("failed to load the teams beneath").Wrap(err)
	}
	below := 0
	for _, t := range subtree {
		below = max(below, t.Depth-team.Depth)
	}

	parentPath, depth := "", 0
	if parentID != "" {
		parent, authErr := s.team(ctx, orgID, parentID)
		if authErr != nil {
			if authErr.Code == types.ErrTeamNotFound {
				return nil, types.NewTeamInvalidParentError("The new parent team does not exist in this organization")
			}
			return nil, authErr
		}
		if strings.HasPrefix(parent.Path, team.Path) {
			return nil, types.NewTeamInvalidParentError("A team cannot move beneath itself or a team beneath it")
		}
		if authErr := s.mustManage(ctx, actor, parent); authErr != nil {
			return nil, authErr
		}
		parentPath, depth = parent.Path, parent.Depth+1
	} else if authErr := s.mustManageOrg(ctx, actor, orgID); authErr != nil {
		return nil, authErr
	}
	if depth+below >= models.MaxTeamDepth {
		return nil, types.NewTeamTooDeepError(models.MaxTeamDepth)
	}
	oldPath := team.Path
	team.ParentID, team.Path, team.Depth = parentID, models.TeamPath(parentPath, team.ID), depth
	if err := s.stores.Teams.Teams().Move(ctx, team, oldPath); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewTeamInvalidParentError("The team changed while it was being moved; try again")
		}
		return nil, types.NewInternalError("failed to move team").Wrap(err)
	}
	s.emit(ctx, types.EventTeamMoved, actor, team, "", "")
	return team, nil
}

func (s *teamService) Delete(ctx context.Context, actor *Actor, orgID, teamID string) *types.GoAuthError {
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return authErr
	}
	if authErr := s.mustManageWhere(ctx, actor, team); authErr != nil {
		return authErr
	}
	if err := s.stores.Teams.Teams().Delete(ctx, team.ID); err != nil {
		switch {
		case errors.Is(err, models.ErrConflict):
			return types.NewTeamHasSubteamsError()
		case errors.Is(err, models.ErrNotFound):
			return types.NewTeamNotFoundError()
		}
		return types.NewInternalError("failed to delete team").Wrap(err)
	}
	s.emit(ctx, types.EventTeamDeleted, actor, team, "", "")
	return nil
}

// --- members ---

func (s *teamService) AddMember(ctx context.Context, actor *Actor, orgID, teamID, userID, role string) (*models.TeamMember, *types.GoAuthError) {
	if role == "" {
		role = models.TeamRoleMember
	}
	if !models.ValidTeamRole(role) {
		return nil, types.NewValidationError("The role must be lead or member")
	}
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return nil, authErr
	}
	if authErr := s.mustManage(ctx, actor, team); authErr != nil {
		return nil, authErr
	}
	membership, authErr := s.orgMember(ctx, orgID, userID)
	if authErr != nil {
		return nil, authErr
	}
	if membership == nil {
		return nil, types.NewOrgMemberNotFoundError()
	}
	if existing, err := s.stores.Teams.Members().FindByTeamAndUser(ctx, teamID, userID); err == nil && existing != nil {
		if existing.MembershipID == membership.ID {
			return nil, types.NewTeamMemberExistsError()
		}
		// Left over from an earlier membership of the organization.
		if err := s.stores.Teams.Members().Delete(ctx, teamID, userID); err != nil {
			return nil, types.NewInternalError("failed to remove a stale team membership").Wrap(err)
		}
	}
	member := &models.TeamMember{ID: newID(), TeamID: teamID, OrgID: orgID, UserID: userID, Role: role, MembershipID: membership.ID}
	if err := s.stores.Teams.Members().Create(ctx, member); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewTeamMemberExistsError()
		}
		return nil, types.NewInternalError("failed to add team member").Wrap(err)
	}
	s.emit(ctx, types.EventTeamMemberAdded, actor, team, userID, role)
	return member, nil
}

func (s *teamService) ChangeMemberRole(ctx context.Context, actor *Actor, orgID, teamID, userID, role string) *types.GoAuthError {
	if !models.ValidTeamRole(role) {
		return types.NewValidationError("The role must be lead or member")
	}
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return authErr
	}
	if authErr := s.mustManage(ctx, actor, team); authErr != nil {
		return authErr
	}
	member, authErr := s.member(ctx, teamID, userID)
	if authErr != nil {
		return authErr
	}
	if member.Role == role {
		return nil
	}
	member.Role = role
	if err := s.stores.Teams.Members().Update(ctx, member); err != nil {
		return types.NewInternalError("failed to change the member's role").Wrap(err)
	}
	s.emit(ctx, types.EventTeamMemberRoleChanged, actor, team, userID, role)
	return nil
}

func (s *teamService) RemoveMember(ctx context.Context, actor *Actor, orgID, teamID, userID string) *types.GoAuthError {
	team, authErr := s.team(ctx, orgID, teamID)
	if authErr != nil {
		return authErr
	}
	// Members may leave a team themselves.
	if actor == nil || actor.UserID != userID {
		if authErr := s.mustManage(ctx, actor, team); authErr != nil {
			return authErr
		}
	}
	member, authErr := s.member(ctx, teamID, userID)
	if authErr != nil {
		return authErr
	}
	if err := s.stores.Teams.Members().Delete(ctx, teamID, userID); err != nil {
		return types.NewInternalError("failed to remove team member").Wrap(err)
	}
	s.emit(ctx, types.EventTeamMemberRemoved, actor, team, userID, member.Role)
	return nil
}

// --- housekeeping ---

func (s *teamService) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	if orgID == "" || userID == "" {
		return nil
	}
	return s.stores.Teams.Members().DeleteByOrgAndUser(ctx, orgID, userID)
}

func (s *teamService) RemoveOrganization(ctx context.Context, orgID string) error {
	if orgID == "" {
		return nil
	}
	return s.stores.Teams.Teams().DeleteByOrg(ctx, orgID)
}

func (s *teamService) RemoveUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return s.stores.Teams.Members().DeleteByUser(ctx, userID)
}

// --- rules ---

func (s *teamService) CanManage(ctx context.Context, actor *Actor, team *models.Team) (bool, *types.GoAuthError) {
	if actor == nil || actor.SuperAdmin {
		return true, nil
	}
	membership, authErr := s.orgMember(ctx, team.OrgID, actor.UserID)
	if authErr != nil || membership == nil {
		return false, authErr
	}
	if membership.Role == "owner" || membership.Role == "admin" {
		return true, nil
	}
	rows, err := s.stores.Teams.Members().ListByTeams(ctx, actor.UserID, team.AncestorIDs())
	if err != nil {
		return false, types.NewInternalError("failed to load team memberships").Wrap(err)
	}
	for _, row := range rows {
		if row.Role == models.TeamRoleLead && row.MembershipID == membership.ID && row.OrgID == team.OrgID {
			return true, nil
		}
	}
	return false, nil
}

func (s *teamService) mustManage(ctx context.Context, actor *Actor, team *models.Team) *types.GoAuthError {
	ok, authErr := s.CanManage(ctx, actor, team)
	if authErr != nil {
		return authErr
	}
	if !ok {
		return types.NewTeamForbiddenError("")
	}
	return nil
}

// mustManageWhere checks the right to manage where a team sits: its parent,
// or the organization for a top-level team.
func (s *teamService) mustManageWhere(ctx context.Context, actor *Actor, team *models.Team) *types.GoAuthError {
	if team.ParentID == "" {
		return s.mustManageOrg(ctx, actor, team.OrgID)
	}
	parent, authErr := s.team(ctx, team.OrgID, team.ParentID)
	if authErr != nil {
		return authErr
	}
	return s.mustManage(ctx, actor, parent)
}

func (s *teamService) mustManageOrg(ctx context.Context, actor *Actor, orgID string) *types.GoAuthError {
	if actor == nil || actor.SuperAdmin {
		return nil
	}
	membership, authErr := s.orgMember(ctx, orgID, actor.UserID)
	if authErr != nil {
		return authErr
	}
	if membership == nil || (membership.Role != "owner" && membership.Role != "admin") {
		return types.NewTeamForbiddenError("Only the organization's owner and admins manage its top-level teams")
	}
	return nil
}

func (s *teamService) canRead(ctx context.Context, actor *Actor, orgID string) *types.GoAuthError {
	if _, authErr := s.organization(ctx, orgID); authErr != nil {
		return authErr
	}
	if actor == nil || actor.SuperAdmin {
		return nil
	}
	membership, authErr := s.orgMember(ctx, orgID, actor.UserID)
	if authErr != nil {
		return authErr
	}
	if membership == nil {
		return types.NewOrgNotFoundError()
	}
	return nil
}

// --- lookups ---

func (s *teamService) organization(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError) {
	org, err := s.stores.Orgs.FindByID(ctx, orgID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (org == nil || org.ID != orgID)) {
		return nil, types.NewOrgNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load organization").Wrap(err)
	}
	return org, nil
}

func (s *teamService) team(ctx context.Context, orgID, teamID string) (*models.Team, *types.GoAuthError) {
	if teamID == "" {
		return nil, types.NewTeamNotFoundError()
	}
	team, err := s.stores.Teams.Teams().FindByID(ctx, teamID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (team == nil || team.ID != teamID || team.OrgID != orgID)) {
		return nil, types.NewTeamNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load team").Wrap(err)
	}
	return team, nil
}

func (s *teamService) member(ctx context.Context, teamID, userID string) (*models.TeamMember, *types.GoAuthError) {
	member, err := s.stores.Teams.Members().FindByTeamAndUser(ctx, teamID, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (member == nil || member.TeamID != teamID || member.UserID != userID)) {
		return nil, types.NewTeamMemberNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load team member").Wrap(err)
	}
	return member, nil
}

// orgMember returns the user's membership in the organization, or nil.
func (s *teamService) orgMember(ctx context.Context, orgID, userID string) (*models.OrganizationMember, *types.GoAuthError) {
	if userID == "" {
		return nil, nil
	}
	member, err := s.stores.Members.FindByOrgAndUser(ctx, orgID, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (member == nil || member.OrgID != orgID || member.UserID != userID)) {
		return nil, nil
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load organization membership").Wrap(err)
	}
	return member, nil
}

func (s *teamService) roomForTeam(ctx context.Context, orgID string) *types.GoAuthError {
	opts := models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: 1}}
	opts.Normalize(1)
	_, total, err := s.stores.Teams.Teams().List(ctx, orgID, opts)
	if err != nil {
		return types.NewInternalError("failed to count teams").Wrap(err)
	}
	if int(total) >= s.maxTeams {
		return types.NewValidationError("This organization has reached its limit of teams")
	}
	return nil
}

func (s *teamService) emit(ctx context.Context, event types.EventType, actor *Actor, team *models.Team, userID, role string) {
	if s.deps.Events == nil {
		return
	}
	actorID := ""
	if actor != nil {
		actorID = actor.UserID
	}
	_ = s.deps.Events.EmitAsync(ctx, event, &types.TeamEventData{
		OrgID: team.OrgID, TeamID: team.ID, TeamName: team.Name, ParentID: team.ParentID, UserID: userID, Role: role, ActorID: actorID,
	})
}

func newID() string { return uuid.Must(uuid.NewV7()).String() }
