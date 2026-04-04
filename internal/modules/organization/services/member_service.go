package services

import (
	"context"
	"errors"

	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type MemberService interface {
	ListMembers(ctx context.Context, orgID string, opts models.MemberListOpts) ([]*dto.MemberWithUser, int64, *types.GoAuthError)
	GetMember(ctx context.Context, orgID, userID string) (*dto.MemberWithUser, *types.GoAuthError)
	UpdateRole(ctx context.Context, orgID, targetUserID string, newRole types.OrgRole, actorID string) *types.GoAuthError
	RemoveMember(ctx context.Context, orgID, targetUserID, actorID string) *types.GoAuthError
}

type memberService struct {
	deps       config.ModuleDependencies
	memberRepo models.OrganizationMemberRepository
	orgRepo    models.OrganizationRepository
	userRepo   models.UserRepository
	maxMembers int
}

func NewMemberService(deps config.ModuleDependencies, memberRepo models.OrganizationMemberRepository, orgRepo models.OrganizationRepository, userRepo models.UserRepository, maxMembers int) *memberService {
	return &memberService{deps: deps, memberRepo: memberRepo, orgRepo: orgRepo, userRepo: userRepo, maxMembers: maxMembers}
}

func (s *memberService) ListMembers(ctx context.Context, orgID string, opts models.MemberListOpts) ([]*dto.MemberWithUser, int64, *types.GoAuthError) {
	members, total, err := s.memberRepo.ListByOrg(ctx, orgID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list members").Wrap(err)
	}

	result := make([]*dto.MemberWithUser, 0, len(members))
	for _, m := range members {
		mwu := &dto.MemberWithUser{OrganizationMember: *m}
		user, err := s.userRepo.FindByID(ctx, m.UserID)
		if err == nil && user != nil {
			user.PasswordHash = ""
			mwu.User = user
		}
		result = append(result, mwu)
	}

	return result, total, nil
}

func (s *memberService) GetMember(ctx context.Context, orgID, userID string) (*dto.MemberWithUser, *types.GoAuthError) {
	member, err := s.memberRepo.FindByOrgAndUser(ctx, orgID, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewOrgMemberNotFoundError()
		}
		return nil, types.NewInternalError("failed to find member").Wrap(err)
	}

	mwu := &dto.MemberWithUser{OrganizationMember: *member}
	user, err := s.userRepo.FindByID(ctx, member.UserID)
	if err == nil && user != nil {
		user.PasswordHash = ""
		mwu.User = user
	}

	return mwu, nil
}

func (s *memberService) UpdateRole(ctx context.Context, orgID, targetUserID string, newRole types.OrgRole, actorID string) *types.GoAuthError {
	if !types.IsValidOrgRole(string(newRole)) {
		return types.NewValidationError("invalid role: must be owner, admin, or member")
	}

	// Get org to check ownership
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewOrgNotFoundError()
		}
		return types.NewInternalError("failed to get organization").Wrap(err)
	}

	// Cannot change owner's role
	if targetUserID == org.OwnerID && newRole != types.OrgRoleOwner {
		return types.NewOrgCannotRemoveOwnerError()
	}

	member, err := s.memberRepo.FindByOrgAndUser(ctx, orgID, targetUserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewOrgMemberNotFoundError()
		}
		return types.NewInternalError("failed to find member").Wrap(err)
	}

	member.Role = string(newRole)
	if err := s.memberRepo.Update(ctx, member); err != nil {
		return types.NewInternalError("failed to update member role").Wrap(err)
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgMemberRoleChanged, &types.OrgMemberEventData{
		OrgID: orgID, OrgName: org.Name, UserID: targetUserID, Role: string(newRole), ActorID: actorID,
	})

	return nil
}

func (s *memberService) RemoveMember(ctx context.Context, orgID, targetUserID, actorID string) *types.GoAuthError {
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewOrgNotFoundError()
		}
		return types.NewInternalError("failed to get organization").Wrap(err)
	}

	// Cannot remove owner
	if targetUserID == org.OwnerID {
		return types.NewOrgCannotRemoveOwnerError()
	}

	_, err = s.memberRepo.FindByOrgAndUser(ctx, orgID, targetUserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewOrgMemberNotFoundError()
		}
		return types.NewInternalError("failed to find member").Wrap(err)
	}

	if err := s.memberRepo.DeleteByOrgAndUser(ctx, orgID, targetUserID); err != nil {
		return types.NewInternalError("failed to remove member").Wrap(err)
	}

	s.deps.Events.EmitAsync(ctx, types.EventOrgMemberRemoved, &types.OrgMemberEventData{
		OrgID: orgID, OrgName: org.Name, UserID: targetUserID, ActorID: actorID,
	})

	return nil
}
