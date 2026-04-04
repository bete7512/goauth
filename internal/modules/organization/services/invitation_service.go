package services

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

type InvitationService interface {
	Invite(ctx context.Context, orgID string, req *dto.InviteRequest, inviterID string) (*models.Invitation, *types.GoAuthError)
	ListInvitations(ctx context.Context, orgID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, *types.GoAuthError)
	CancelInvitation(ctx context.Context, orgID, invID string) *types.GoAuthError
	AcceptInvitation(ctx context.Context, userID, userEmail, token string) (*models.OrganizationMember, *types.GoAuthError)
	DeclineInvitation(ctx context.Context, userID, token string) *types.GoAuthError
	ListPendingByEmail(ctx context.Context, email string) ([]*models.Invitation, *types.GoAuthError)
}

type invitationService struct {
	deps             config.ModuleDependencies
	invitationRepo   models.InvitationRepository
	memberRepo       models.OrganizationMemberRepository
	orgRepo          models.OrganizationRepository
	userRepo         models.UserRepository
	invitationExpiry time.Duration
	callbackURL      string
	maxMembersPerOrg int
}

func NewInvitationService(
	deps config.ModuleDependencies,
	invitationRepo models.InvitationRepository,
	memberRepo models.OrganizationMemberRepository,
	orgRepo models.OrganizationRepository,
	userRepo models.UserRepository,
	invitationExpiry time.Duration,
	callbackURL string,
	maxMembersPerOrg int,
) *invitationService {
	return &invitationService{
		deps:             deps,
		invitationRepo:   invitationRepo,
		memberRepo:       memberRepo,
		orgRepo:          orgRepo,
		userRepo:         userRepo,
		invitationExpiry: invitationExpiry,
		callbackURL:      callbackURL,
		maxMembersPerOrg: maxMembersPerOrg,
	}
}

func (s *invitationService) Invite(ctx context.Context, orgID string, req *dto.InviteRequest, inviterID string) (*models.Invitation, *types.GoAuthError) {
	role := req.Role
	if role == "" {
		role = string(types.OrgRoleMember)
	}
	if !types.IsValidOrgRole(role) {
		return nil, types.NewValidationError("invalid role: must be owner, admin, or member")
	}

	// Check if invitee is already a member (by email lookup)
	// Non-critical lookup: error means user doesn't exist yet, which is fine
	user, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if user != nil {
		// Non-critical lookup: error means no membership, which is expected for new invites
		existingMember, _ := s.memberRepo.FindByOrgAndUser(ctx, orgID, user.ID)
		if existingMember != nil {
			return nil, types.NewOrgMemberExistsError()
		}
	}

	// Check for duplicate pending invitation
	// Non-critical lookup: error means no existing invitation, which is the expected case
	existingInv, _ := s.invitationRepo.FindByOrgAndEmail(ctx, orgID, req.Email)
	if existingInv != nil {
		return nil, types.NewInvitationExistsError()
	}

	// Check member limit
	if s.maxMembersPerOrg > 0 {
		count, err := s.memberRepo.CountByOrg(ctx, orgID)
		if err != nil {
			return nil, types.NewInternalError("failed to count members").Wrap(err)
		}
		if count >= int64(s.maxMembersPerOrg) {
			return nil, types.NewOrgMaxMembersError()
		}
	}

	// Generate token
	token, tokenErr := s.deps.SecurityManager.GenerateRandomToken(32)
	if tokenErr != nil {
		return nil, types.NewInternalError("failed to generate invitation token").Wrap(tokenErr)
	}

	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewOrgNotFoundError()
		}
		return nil, types.NewInternalError("failed to get organization").Wrap(err)
	}

	// Get inviter name (non-critical lookup: inviter name is optional display info)
	inviter, _ := s.userRepo.FindByID(ctx, inviterID)
	inviterName := ""
	if inviter != nil {
		inviterName = inviter.Name
	}

	invitation := &models.Invitation{
		ID:        uuid.Must(uuid.NewV7()).String(),
		OrgID:     orgID,
		Email:     req.Email,
		Role:      role,
		InviterID: inviterID,
		Token:     token,
		Status:    models.InvitationStatusPending,
		ExpiresAt: time.Now().Add(s.invitationExpiry),
		CreatedAt: time.Now(),
	}

	if err := s.invitationRepo.Create(ctx, invitation); err != nil {
		return nil, types.NewInternalError("failed to create invitation").Wrap(err)
	}

	// Build invite link
	inviteLink := ""
	if s.callbackURL != "" {
		inviteLink = s.callbackURL + "?token=" + token
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgInvitationSent, &types.OrgInvitationEventData{
		OrgID:       orgID,
		OrgName:     org.Name,
		Email:       req.Email,
		Role:        role,
		InviterID:   inviterID,
		InviterName: inviterName,
		InviteLink:  inviteLink,
		ExpiresAt:   invitation.ExpiresAt,
	})

	return invitation, nil
}

func (s *invitationService) ListInvitations(ctx context.Context, orgID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, *types.GoAuthError) {
	invitations, total, err := s.invitationRepo.ListByOrg(ctx, orgID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list invitations").Wrap(err)
	}
	return invitations, total, nil
}

func (s *invitationService) CancelInvitation(ctx context.Context, orgID, invID string) *types.GoAuthError {
	inv, err := s.invitationRepo.FindByID(ctx, invID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewInvitationNotFoundError()
		}
		return types.NewInternalError("failed to find invitation").Wrap(err)
	}
	if inv.OrgID != orgID {
		return types.NewInvitationNotFoundError()
	}
	if err := s.invitationRepo.Delete(ctx, invID); err != nil {
		return types.NewInternalError("failed to cancel invitation").Wrap(err)
	}
	return nil
}

func (s *invitationService) AcceptInvitation(ctx context.Context, userID, userEmail, token string) (*models.OrganizationMember, *types.GoAuthError) {
	inv, err := s.invitationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInvitationNotFoundError()
		}
		return nil, types.NewInternalError("failed to find invitation").Wrap(err)
	}
	if inv.Status != models.InvitationStatusPending {
		return nil, types.NewInvitationNotFoundError()
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, types.NewInvitationExpiredError()
	}
	if inv.Email != userEmail {
		return nil, types.NewInvitationEmailMismatchError()
	}

	// Check not already a member (non-critical lookup: error means no membership found, which is expected)
	existing, _ := s.memberRepo.FindByOrgAndUser(ctx, inv.OrgID, userID)
	if existing != nil {
		return nil, types.NewOrgMemberExistsError()
	}

	now := time.Now()
	member := &models.OrganizationMember{
		ID:       uuid.Must(uuid.NewV7()).String(),
		OrgID:    inv.OrgID,
		UserID:   userID,
		Role:     inv.Role,
		JoinedAt: now,
	}

	if err := s.memberRepo.Create(ctx, member); err != nil {
		return nil, types.NewInternalError("failed to create membership").Wrap(err)
	}

	// Update invitation status — write operation, handle the error
	inv.Status = models.InvitationStatusAccepted
	inv.AcceptedAt = &now
	if err := s.invitationRepo.Update(ctx, inv); err != nil {
		return nil, types.NewInternalError("failed to update invitation status").Wrap(err)
	}

	// Non-critical lookup: org name is optional display info for event
	org, _ := s.orgRepo.FindByID(ctx, inv.OrgID)
	orgName := ""
	if org != nil {
		orgName = org.Name
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgInvitationAccepted, &types.OrgMemberEventData{
		OrgID: inv.OrgID, OrgName: orgName, UserID: userID, Email: userEmail, Role: inv.Role,
	})
	s.deps.Events.EmitAsync(ctx, types.EventOrgMemberAdded, &types.OrgMemberEventData{
		OrgID: inv.OrgID, OrgName: orgName, UserID: userID, Email: userEmail, Role: inv.Role,
	})

	return member, nil
}

func (s *invitationService) DeclineInvitation(ctx context.Context, userID, token string) *types.GoAuthError {
	inv, err := s.invitationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewInvitationNotFoundError()
		}
		return types.NewInternalError("failed to find invitation").Wrap(err)
	}
	if inv.Status != models.InvitationStatusPending {
		return types.NewInvitationNotFoundError()
	}

	inv.Status = models.InvitationStatusDeclined
	// Write operation, handle the error
	if err := s.invitationRepo.Update(ctx, inv); err != nil {
		return types.NewInternalError("failed to update invitation status").Wrap(err)
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgInvitationDeclined, &types.OrgInvitationEventData{
		OrgID: inv.OrgID, Email: inv.Email,
	})

	return nil
}

func (s *invitationService) ListPendingByEmail(ctx context.Context, email string) ([]*models.Invitation, *types.GoAuthError) {
	invitations, err := s.invitationRepo.ListPendingByEmail(ctx, email)
	if err != nil {
		return nil, types.NewInternalError("failed to list invitations").Wrap(err)
	}
	return invitations, nil
}
