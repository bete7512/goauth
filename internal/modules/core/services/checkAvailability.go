package core_services

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

func (s *coreService) CheckEmailAvailability(ctx context.Context, email string) (*dto.CheckAvailabilityResponse, *types.GoAuthError) {
	available, err := s.UserRepository.IsAvailable(ctx, "email", email)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to check email availability: %v", err))
	}
	return &dto.CheckAvailabilityResponse{Available: available}, nil
}

func (s *coreService) CheckUsernameAvailability(ctx context.Context, username string) (*dto.CheckAvailabilityResponse, *types.GoAuthError) {
	available, err := s.UserRepository.IsAvailable(ctx, "username", username)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to check username availability: %v", err))
	}
	return &dto.CheckAvailabilityResponse{Available: available}, nil
}

func (s *coreService) CheckPhoneAvailability(ctx context.Context, phone string) (*dto.CheckAvailabilityResponse, *types.GoAuthError) {
	available, err := s.UserRepository.IsAvailable(ctx, "phone_number", phone)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to check phone availability: %v", err))
	}
	return &dto.CheckAvailabilityResponse{Available: available}, nil
}
