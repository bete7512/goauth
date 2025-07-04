package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
)

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.UserResponse{
		Message: "user retrieved successfully",
		User:    s.mapUserToDTO(user),
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Update fields if provided
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = &req.PhoneNumber
	}

	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &dto.UserResponse{
		Message: "profile updated successfully",
		User:    s.mapUserToDTO(user),
	}, nil
}

// DeactivateUser deactivates a user account
func (s *AuthService) DeactivateUser(ctx context.Context, userID string, req *dto.DeactivateUserRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	active := false
	user.Active = &active
	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	return nil
}

func (s *AuthService) GetMe(ctx context.Context, userID string) (*dto.UserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.UserResponse{
		Message: "user retrieved successfully",
		User:    s.mapUserToDTO(user),
	}, nil
}
