package core_services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
)

// GetProfile retrieves user profile
func (s *CoreService) GetProfile(ctx context.Context, userID string) (*dto.UserDTO, error) {
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.UserDTO{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		Name:          user.Name,
		Phone:         user.Phone,
		Avatar:        user.Avatar,
		Active:        user.Active,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// UpdateProfile updates user profile
func (s *CoreService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserDTO, error) {
	// Find user
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Check if phone is being changed and if it's already taken
	if req.Phone != "" && req.Phone != user.Phone {
		existing, _ := s.UserRepository.FindByPhone(ctx, req.Phone)
		if existing != nil && existing.ID != user.ID {
			return nil, errors.New("phone number already in use")
		}
		// Mark phone as unverified if changed
		user.Phone = req.Phone
		user.PhoneVerified = false
	}

	// Update fields
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}

	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	// Emit event
	s.deps.Events.Emit(ctx, "profile:updated", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return &dto.UserDTO{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		Name:          user.Name,
		Phone:         user.Phone,
		Avatar:        user.Avatar,
		Active:        user.Active,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
	}, nil
}
