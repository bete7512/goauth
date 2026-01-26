package core_services

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// GetCurrentUser retrieves user by user ID (from JWT claims)
func (s *CoreService) GetCurrentUser(ctx context.Context, userID string) (*dto.UserDTO, *types.GoAuthError) {
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	return &dto.UserDTO{
		ID:                  user.ID,
		Email:               user.Email,
		Username:            user.Username,
		Name:                user.Name,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		PhoneNumber:         user.PhoneNumber,
		Avatar:              user.Avatar,
		Active:              user.Active,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: user.PhoneNumberVerified,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		LastLoginAt:         user.LastLoginAt,
		ExtendedAttributes: func() []dto.ExtendedAttributes {
			attrs := make([]dto.ExtendedAttributes, len(user.ExtendedAttributes))
			for i, attr := range user.ExtendedAttributes {
				attrs[i] = dto.ExtendedAttributes{Name: attr.Name, Value: attr.Value}
			}
			return attrs
		}(),
	}, nil
}
