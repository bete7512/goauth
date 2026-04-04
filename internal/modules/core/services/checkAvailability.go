package core_services

import (
	"context"

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
		return nil, types.NewInternalError("failed to check " + field + " availability").Wrap(err)
	}

	return &dto.CheckAvailabilityResponse{
		Available: available,
		Field:     field,
	}, nil
}
