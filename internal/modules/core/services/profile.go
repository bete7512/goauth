package core_services

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// UpdateProfile updates user profile
func (s *coreService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserDTO, *types.GoAuthError) {
	// Find user
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}
	now := time.Now()
	// Update fields
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Phone != "" {
		if req.Phone != user.PhoneNumber {
			user.PhoneNumberVerified = false
			user.TokenVersion++
		}
		user.PhoneNumber = req.Phone
	}
	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}

	user.UpdatedAt = &now

	var updateErr error
	if mutator, ok := s.UserRepository.(models.UserProfileMutator); ok {
		updateErr = mutator.UpdateProfile(ctx, userID, req.Name, req.Phone, req.Avatar)
	} else {
		updateErr = s.UserRepository.Update(ctx, user)
	}
	if err := updateErr; err != nil {
		return nil, types.NewInternalError("failed to update profile").Wrap(err)
	}

	return &dto.UserDTO{
		ID:          user.ID,
		Email:       user.Email,
		Name:        user.Name,
		PhoneNumber: user.PhoneNumber,
		Avatar:      user.Avatar,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}, nil
}
