package core_services

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

func (s *coreService) CheckAvailability(ctx context.Context, req *dto.CheckAvailabilityRequest) (*dto.CheckAvailabilityResponse, *types.GoAuthError) {
	var field, column, value string

	switch {
	case req.Email != "":
		field, column, value = "email", "email", req.Email
	case req.Username != "":
		field, column, value = "username", "username", req.Username
	case req.Phone != "":
		field, column, value = "phone", "phone_number", req.Phone
	default:
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "email, username, or phone is required", 400)
	}

	available, err := s.UserRepository.IsAvailable(ctx, column, value)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to check %s availability: %v", field, err))
	}

	return &dto.CheckAvailabilityResponse{
		Available: available,
		Field:     field,
	}, nil
}
