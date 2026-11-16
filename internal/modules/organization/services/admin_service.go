package services

//go:generate mockgen -destination=../../../mocks/mock_org_admin_service.go -package=mocks -mock_names=AdminService=MockOrgAdminService github.com/bete7512/goauth/internal/modules/organization/services AdminService

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// AdminMember is a membership with its user, for administrators.
type AdminMember struct {
	Member *models.OrganizationMember
	User   *models.User // nil when the user no longer exists
}

// AdminMembership is one organization a user belongs to.
type AdminMembership struct {
	Member       *models.OrganizationMember
	Organization *models.Organization
}

// AdminService is the platform administrators' view of organizations. Every
// method requires the caller in the context to be an active super admin;
// organization owners and admins use OrgService and MemberService instead.
type AdminService interface {
	ListOrganizations(ctx context.Context, opts models.OrganizationListOpts) ([]*models.Organization, int64, *types.GoAuthError)
	GetOrganization(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError)
	// SetActive suspends or restores an organization. While it is inactive
	// nobody can select it, and tokens already selecting it stop working.
	SetActive(ctx context.Context, orgID string, active bool) *types.GoAuthError
	// DeleteOrganization removes the organization with its memberships and
	// invitations.
	DeleteOrganization(ctx context.Context, orgID string) *types.GoAuthError
	ListMembers(ctx context.Context, orgID string, opts models.MemberListOpts) ([]AdminMember, int64, *types.GoAuthError)
	// ChangeMemberRole sets a member's role to admin or member. The owner's
	// role changes only through TransferOwnership.
	ChangeMemberRole(ctx context.Context, orgID, userID string, role types.OrgRole) *types.GoAuthError
	// RemoveMember removes a member other than the owner.
	RemoveMember(ctx context.Context, orgID, userID string) *types.GoAuthError
	// TransferOwnership makes an existing member the owner; the previous
	// owner stays on as an admin.
	TransferOwnership(ctx context.Context, orgID, newOwnerID string) *types.GoAuthError
	ListInvitations(ctx context.Context, orgID string, opts models.OrgInvitationListOpts) ([]*models.OrgInvitation, int64, *types.GoAuthError)
	CancelInvitation(ctx context.Context, orgID, invitationID string) *types.GoAuthError
	// InviteMember sends an invitation as the acting super admin.
	InviteMember(ctx context.Context, orgID, email, role string) (*models.OrgInvitation, *types.GoAuthError)
	// ListUserMemberships returns every organization a user belongs to.
	ListUserMemberships(ctx context.Context, userID string) ([]AdminMembership, *types.GoAuthError)
	// CreateOrganization creates an organization owned by an existing user,
	// as that user creating it would. An empty slug is derived from the name.
	CreateOrganization(ctx context.Context, ownerEmail, name, slug string) (*models.Organization, *types.GoAuthError)
	// UpdateOrganization changes an organization's name and logo.
	UpdateOrganization(ctx context.Context, orgID, name, logoURL string) (*models.Organization, *types.GoAuthError)
	// AddMember adds an existing user to an organization directly, without
	// an invitation, as an admin or member.
	AddMember(ctx context.Context, orgID, email string, role types.OrgRole) *types.GoAuthError
}

type adminService struct {
	deps        config.ModuleDependencies
	store       types.OrganizationStorage
	users       models.UserRepository
	invitations *invitationService
}

// NewAdminService creates the administrators' organization service.
// invitations sends the invitations administrators make; it may be nil,
// and inviting is then unavailable.
func NewAdminService(deps config.ModuleDependencies, store types.OrganizationStorage, users models.UserRepository, invitations *invitationService) *adminService {
	return &adminService{deps: deps, store: store, users: users, invitations: invitations}
}

// InviteMember sends an invitation to join an organization, as the acting
// super admin, with the same rules as the organization's own invitations
// (no duplicates, no existing members, the member limit) except the rank of
// the inviter.
func (s *adminService) InviteMember(ctx context.Context, orgID, email, role string) (*models.OrgInvitation, *types.GoAuthError) {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return nil, authErr
	}
	if s.invitations == nil {
		return nil, types.NewInternalError("organization invitations are unavailable")
	}
	req := &dto.InviteRequest{Email: strings.TrimSpace(email), Role: role}
	if err := req.Validate(); err != nil {
		return nil, types.NewValidationError(err.Error())
	}
	return s.invitations.invite(ctx, orgID, req, actor.ID, false)
}

// authorize returns the acting super admin.
func (s *adminService) authorize(ctx context.Context) (*models.User, *types.GoAuthError) {
	principal, ok := types.PrincipalFromContext(ctx)
	if !ok || principal.UserID == "" {
		return nil, types.NewUnauthorizedError()
	}
	actor, err := s.users.FindByID(ctx, principal.UserID)
	if err != nil || actor == nil || !actor.Active || !actor.IsSuperAdmin {
		return nil, types.NewForbiddenError()
	}
	return actor, nil
}

func (s *adminService) ListOrganizations(ctx context.Context, opts models.OrganizationListOpts) ([]*models.Organization, int64, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, 0, authErr
	}
	orgs, total, err := s.store.Organizations().List(ctx, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list organizations").Wrap(err)
	}
	return orgs, total, nil
}

func (s *adminService) GetOrganization(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, authErr
	}
	return s.find(ctx, orgID)
}

func (s *adminService) find(ctx context.Context, orgID string) (*models.Organization, *types.GoAuthError) {
	org, err := s.store.Organizations().FindByID(ctx, orgID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (org == nil || org.ID != orgID)) {
		return nil, types.NewOrgNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load organization").Wrap(err)
	}
	return org, nil
}

func (s *adminService) SetActive(ctx context.Context, orgID string, active bool) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	if org.Active == active {
		return nil
	}
	org.Active = active
	now := time.Now()
	org.UpdatedAt = &now
	if err := s.store.Organizations().Update(ctx, org); err != nil {
		return types.NewInternalError("failed to update organization").Wrap(err)
	}
	_ = s.deps.Events.EmitAsync(ctx, types.EventOrgUpdated, &types.OrgEventData{Organization: org, ActorID: actor.ID})
	return nil
}

func (s *adminService) DeleteOrganization(ctx context.Context, orgID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	if err := s.store.Organizations().Delete(ctx, org.ID); err != nil {
		return types.NewInternalError("failed to delete organization").Wrap(err)
	}
	_ = s.deps.Events.EmitAsync(ctx, types.EventOrgDeleted, &types.OrgEventData{Organization: org, ActorID: actor.ID})
	return nil
}

func (s *adminService) ListMembers(ctx context.Context, orgID string, opts models.MemberListOpts) ([]AdminMember, int64, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, 0, authErr
	}
	if _, authErr := s.find(ctx, orgID); authErr != nil {
		return nil, 0, authErr
	}
	members, total, err := s.store.Members().ListByOrg(ctx, orgID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list members").Wrap(err)
	}
	out := make([]AdminMember, 0, len(members))
	for _, member := range members {
		user, err := s.users.FindByID(ctx, member.UserID)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, 0, types.NewInternalError("failed to load member").Wrap(err)
		}
		out = append(out, AdminMember{Member: member, User: user})
	}
	return out, total, nil
}

// member returns a membership of an organization, checked against both IDs.
func (s *adminService) member(ctx context.Context, orgID, userID string) (*models.OrganizationMember, *types.GoAuthError) {
	member, err := s.store.Members().FindByOrgAndUser(ctx, orgID, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (member == nil || member.OrgID != orgID || member.UserID != userID)) {
		return nil, types.NewOrgMemberNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load member").Wrap(err)
	}
	return member, nil
}

func (s *adminService) ChangeMemberRole(ctx context.Context, orgID, userID string, role types.OrgRole) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	if role != types.OrgRoleAdmin && role != types.OrgRoleMember {
		return types.NewValidationError("role must be admin or member; use ownership transfer to change the owner")
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	member, authErr := s.member(ctx, orgID, userID)
	if authErr != nil {
		return authErr
	}
	if userID == org.OwnerID || member.Role == string(types.OrgRoleOwner) {
		return types.NewOrgCannotRemoveOwnerError()
	}
	if member.Role == string(role) {
		return nil
	}
	member.Role = string(role)
	if err := s.store.Members().Update(ctx, member); err != nil {
		return types.NewInternalError("failed to update member").Wrap(err)
	}
	s.memberEvent(ctx, types.EventOrgMemberRoleChanged, org, member, actor.ID)
	return nil
}

func (s *adminService) RemoveMember(ctx context.Context, orgID, userID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	member, authErr := s.member(ctx, orgID, userID)
	if authErr != nil {
		return authErr
	}
	if userID == org.OwnerID || member.Role == string(types.OrgRoleOwner) {
		return types.NewOrgCannotRemoveOwnerError()
	}
	if err := s.store.Members().DeleteByOrgAndUser(ctx, orgID, userID); err != nil {
		return types.NewInternalError("failed to remove member").Wrap(err)
	}
	s.memberEvent(ctx, types.EventOrgMemberRemoved, org, member, actor.ID)
	return nil
}

func (s *adminService) TransferOwnership(ctx context.Context, orgID, newOwnerID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	if newOwnerID == org.OwnerID {
		return nil
	}
	next, authErr := s.member(ctx, orgID, newOwnerID)
	if authErr != nil {
		return authErr
	}
	user, err := s.users.FindByID(ctx, newOwnerID)
	if err != nil || user == nil || !user.Active {
		return types.NewValidationError("the new owner must be an active user")
	}
	previousOwner := org.OwnerID
	var previous *models.OrganizationMember
	err = s.store.WithTransaction(ctx, func(tx types.OrganizationStorage) error {
		now := time.Now()
		org.OwnerID = newOwnerID
		org.UpdatedAt = &now
		if err := tx.Organizations().Update(ctx, org); err != nil {
			return err
		}
		next.Role = string(types.OrgRoleOwner)
		if err := tx.Members().Update(ctx, next); err != nil {
			return err
		}
		old, err := tx.Members().FindByOrgAndUser(ctx, orgID, previousOwner)
		if errors.Is(err, models.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		old.Role = string(types.OrgRoleAdmin)
		previous = old
		return tx.Members().Update(ctx, old)
	})
	if err != nil {
		return types.NewInternalError("failed to transfer ownership").Wrap(err)
	}
	_ = s.deps.Events.EmitAsync(ctx, types.EventOrgUpdated, &types.OrgEventData{Organization: org, ActorID: actor.ID})
	s.memberEvent(ctx, types.EventOrgMemberRoleChanged, org, next, actor.ID)
	if previous != nil {
		s.memberEvent(ctx, types.EventOrgMemberRoleChanged, org, previous, actor.ID)
	}
	return nil
}

func (s *adminService) ListInvitations(ctx context.Context, orgID string, opts models.OrgInvitationListOpts) ([]*models.OrgInvitation, int64, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, 0, authErr
	}
	if _, authErr := s.find(ctx, orgID); authErr != nil {
		return nil, 0, authErr
	}
	invitations, total, err := s.store.Invitations().ListByOrg(ctx, orgID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list invitations").Wrap(err)
	}
	return invitations, total, nil
}

func (s *adminService) CancelInvitation(ctx context.Context, orgID, invitationID string) *types.GoAuthError {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return authErr
	}
	invitation, err := s.store.Invitations().FindByID(ctx, invitationID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (invitation == nil || invitation.OrgID != orgID)) {
		return types.NewInvitationNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load invitation").Wrap(err)
	}
	if err := s.store.Invitations().Delete(ctx, invitation.ID); err != nil {
		return types.NewInternalError("failed to cancel invitation").Wrap(err)
	}
	return nil
}

func (s *adminService) ListUserMemberships(ctx context.Context, userID string) ([]AdminMembership, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, authErr
	}
	members, err := s.store.Members().ListByUser(ctx, userID)
	if err != nil {
		return nil, types.NewInternalError("failed to list memberships").Wrap(err)
	}
	out := make([]AdminMembership, 0, len(members))
	for _, member := range members {
		org, err := s.store.Organizations().FindByID(ctx, member.OrgID)
		if err != nil || org == nil {
			continue
		}
		out = append(out, AdminMembership{Member: member, Organization: org})
	}
	return out, nil
}

func (s *adminService) memberEvent(ctx context.Context, event types.EventType, org *models.Organization, member *models.OrganizationMember, actorID string) {
	data := &types.OrgMemberEventData{OrgID: org.ID, OrgName: org.Name, UserID: member.UserID, Role: member.Role, ActorID: actorID}
	if user, err := s.users.FindByID(ctx, member.UserID); err == nil && user != nil {
		data.Email = user.Email
	}
	_ = s.deps.Events.EmitAsync(ctx, event, data)
}

func (s *adminService) userByEmail(ctx context.Context, email string) (*models.User, *types.GoAuthError) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, types.NewValidationError("Enter the user's email address")
	}
	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, models.ErrNotFound) || (err == nil && user == nil) {
		return nil, types.NewUserNotFoundError()
	}
	if err != nil {
		return nil, types.NewInternalError("failed to load user").Wrap(err)
	}
	return user, nil
}

func (s *adminService) CreateOrganization(ctx context.Context, ownerEmail, name, slug string) (*models.Organization, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, authErr
	}
	owner, authErr := s.userByEmail(ctx, ownerEmail)
	if authErr != nil {
		return nil, authErr
	}
	request := &dto.CreateOrgRequest{Name: strings.TrimSpace(name), Slug: strings.TrimSpace(slug)}
	if err := request.Validate(); err != nil {
		return nil, types.NewValidationError(err.Error())
	}
	return NewOrgService(s.deps, s.store.Organizations(), s.store.Members(), s.users).Create(ctx, owner.ID, request)
}

func (s *adminService) UpdateOrganization(ctx context.Context, orgID, name, logoURL string) (*models.Organization, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, authErr
	}
	name, logoURL = strings.TrimSpace(name), strings.TrimSpace(logoURL)
	if name == "" {
		return nil, types.NewValidationError("Name is required")
	}
	return NewOrgService(s.deps, s.store.Organizations(), s.store.Members(), s.users).Update(ctx, orgID, &dto.UpdateOrgRequest{Name: &name, LogoURL: &logoURL})
}

func (s *adminService) AddMember(ctx context.Context, orgID, email string, role types.OrgRole) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	if role != types.OrgRoleAdmin && role != types.OrgRoleMember {
		return types.NewValidationError("role must be admin or member")
	}
	org, authErr := s.find(ctx, orgID)
	if authErr != nil {
		return authErr
	}
	user, authErr := s.userByEmail(ctx, email)
	if authErr != nil {
		return authErr
	}
	if existing, err := s.store.Members().FindByOrgAndUser(ctx, orgID, user.ID); err == nil && existing != nil {
		return types.NewOrgMemberExistsError()
	} else if err != nil && !errors.Is(err, models.ErrNotFound) {
		return types.NewInternalError("failed to check membership").Wrap(err)
	}
	member := &models.OrganizationMember{OrgID: orgID, UserID: user.ID, Role: string(role), JoinedAt: time.Now()}
	if err := s.store.Members().Create(ctx, member); err != nil {
		return types.NewInternalError("failed to add member").Wrap(err)
	}
	s.memberEvent(ctx, types.EventOrgMemberAdded, org, member, actor.ID)
	return nil
}
