package services

//go:generate mockgen -destination=../../../../internal/mocks/mock_platform_invitation_service.go -package=mocks github.com/bete7512/goauth/internal/modules/invitation/services InvitationService

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/invitation/handlers/dto"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// InvitationService defines standalone invitation operations.
type InvitationService interface {
	Send(ctx context.Context, req *dto.SendInvitationRequest, inviterID string) (*models.Invitation, *types.GoAuthError)
	List(ctx context.Context, inviterID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, *types.GoAuthError)
	Cancel(ctx context.Context, invID, inviterID string) *types.GoAuthError
	Accept(ctx context.Context, userID, userEmail, token string) *types.GoAuthError
	Decline(ctx context.Context, userID, token string) *types.GoAuthError
	ListPendingByEmail(ctx context.Context, email string) ([]*models.Invitation, *types.GoAuthError)
}

type invitationService struct {
	deps               config.ModuleDependencies
	invitationRepo     models.InvitationRepository
	userRepo           models.UserRepository
	invitationExpiry   time.Duration
	callbackURL        string
	defaultPurpose     string
	allowedPurposes    []string
	maxPendingPerEmail int
}

func NewInvitationService(
	deps config.ModuleDependencies,
	invitationRepo models.InvitationRepository,
	userRepo models.UserRepository,
	invitationExpiry time.Duration,
	callbackURL string,
	defaultPurpose string,
	allowedPurposes []string,
	maxPendingPerEmail int,
) *invitationService {
	return &invitationService{
		deps:               deps,
		invitationRepo:     invitationRepo,
		userRepo:           userRepo,
		invitationExpiry:   invitationExpiry,
		callbackURL:        callbackURL,
		defaultPurpose:     defaultPurpose,
		allowedPurposes:    allowedPurposes,
		maxPendingPerEmail: maxPendingPerEmail,
	}
}

func (s *invitationService) Send(ctx context.Context, req *dto.SendInvitationRequest, inviterID string) (*models.Invitation, *types.GoAuthError) {
	purpose := req.Purpose
	if purpose == "" {
		purpose = s.defaultPurpose
	}

	// Validate purpose if allowlist is configured
	if len(s.allowedPurposes) > 0 {
		allowed := false
		for _, p := range s.allowedPurposes {
			if p == purpose {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, types.NewValidationError(fmt.Sprintf("invalid purpose: %s", purpose))
		}
	}

	// Check for duplicate pending invitation (same email + purpose)
	existingInv, _ := s.invitationRepo.FindPendingByEmail(ctx, req.Email, purpose)
	if existingInv != nil {
		return nil, types.NewInvitationExistsError()
	}

	// Generate token
	token, tokenErr := s.deps.SecurityManager.GenerateRandomToken(32)
	if tokenErr != nil {
		return nil, types.NewInternalError("failed to generate invitation token").Wrap(tokenErr)
	}

	// Get inviter name (non-critical lookup)
	inviter, _ := s.userRepo.FindByID(ctx, inviterID)
	inviterName := ""
	if inviter != nil {
		inviterName = inviter.Name
	}

	invitation := &models.Invitation{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Email:     req.Email,
		Purpose:   purpose,
		InviterID: inviterID,
		Token:     token,
		Status:    models.InvitationStatusPending,
		Metadata:  req.Metadata,
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

	s.deps.Events.EmitAsync(ctx, types.EventInvitationSent, &types.InvitationEventData{
		InvitationID: invitation.ID,
		Email:        req.Email,
		Purpose:      purpose,
		InviterID:    inviterID,
		InviterName:  inviterName,
		InviteLink:   inviteLink,
		Metadata:     req.Metadata,
		ExpiresAt:    invitation.ExpiresAt,
	})

	return invitation, nil
}

func (s *invitationService) List(ctx context.Context, inviterID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, *types.GoAuthError) {
	invitations, total, err := s.invitationRepo.ListByInviter(ctx, inviterID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list invitations").Wrap(err)
	}
	return invitations, total, nil
}

func (s *invitationService) Cancel(ctx context.Context, invID, inviterID string) *types.GoAuthError {
	inv, err := s.invitationRepo.FindByID(ctx, invID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewInvitationNotFoundError()
		}
		return types.NewInternalError("failed to find invitation").Wrap(err)
	}
	if inv.InviterID != inviterID {
		return types.NewInvitationNotFoundError()
	}
	if err := s.invitationRepo.Delete(ctx, invID); err != nil {
		return types.NewInternalError("failed to cancel invitation").Wrap(err)
	}
	return nil
}

func (s *invitationService) Accept(ctx context.Context, userID, userEmail, token string) *types.GoAuthError {
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
	if time.Now().After(inv.ExpiresAt) {
		return types.NewInvitationExpiredError()
	}
	if inv.Email != userEmail {
		return types.NewInvitationEmailMismatchError()
	}

	now := time.Now()
	inv.Status = models.InvitationStatusAccepted
	inv.AcceptedAt = &now
	if err := s.invitationRepo.Update(ctx, inv); err != nil {
		return types.NewInternalError("failed to update invitation status").Wrap(err)
	}

	s.deps.Events.EmitAsync(ctx, types.EventInvitationAccepted, &types.InvitationEventData{
		InvitationID: inv.ID,
		Email:        inv.Email,
		Purpose:      inv.Purpose,
		InviterID:    inv.InviterID,
		Metadata:     inv.Metadata,
		ExpiresAt:    inv.ExpiresAt,
	})

	return nil
}

func (s *invitationService) Decline(ctx context.Context, userID, token string) *types.GoAuthError {
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
	if err := s.invitationRepo.Update(ctx, inv); err != nil {
		return types.NewInternalError("failed to update invitation status").Wrap(err)
	}

	s.deps.Events.EmitAsync(ctx, types.EventInvitationDeclined, &types.InvitationEventData{
		InvitationID: inv.ID,
		Email:        inv.Email,
		Purpose:      inv.Purpose,
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
