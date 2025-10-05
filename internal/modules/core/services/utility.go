package core_services

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// CheckAvailability checks if email, username, or phone is available
func (s *CoreService) CheckAvailability(ctx context.Context, req *dto.CheckAvailabilityRequest) (*dto.CheckAvailabilityResponse, *types.GoAuthError) {
	if req.Email != "" {
		user, _ := s.UserRepository.FindByEmail(ctx, req.Email)
		if user != nil {
			return &dto.CheckAvailabilityResponse{
				Available: false,
				Field:     "email",
				Message:   "Email is already taken",
			}, nil
		}
		return &dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "email",
			Message:   "Email is available",
		}, nil
	}

	if req.Username != "" {
		user, _ := s.UserRepository.FindByUsername(ctx, req.Username)
		if user != nil {
			return &dto.CheckAvailabilityResponse{
				Available: false,
				Field:     "username",
				Message:   "Username is already taken",
			}, nil
		}
		return &dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "username",
			Message:   "Username is available",
		}, nil
	}

	if req.Phone != "" {
		user, _ := s.UserRepository.FindByPhone(ctx, req.Phone)
		if user != nil {
			return &dto.CheckAvailabilityResponse{
				Available: false,
				Field:     "phone",
				Message:   "Phone number is already taken",
			}, nil
		}
		return &dto.CheckAvailabilityResponse{
			Available: true,
			Field:     "phone",
			Message:   "Phone number is available",
		}, nil
	}

	return &dto.CheckAvailabilityResponse{
		Available: false,
		Field:     "unknown",
		Message:   "No field provided for availability check",
	}, nil
}
