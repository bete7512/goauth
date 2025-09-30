package auth_service

import (
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

func (s *AuthService) mapUserToDTO(user *models.User) dto.UserResponseData {
	if user == nil {
		return dto.UserResponseData{}
	}
	return dto.UserResponseData{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    user.EmailVerified,
		PhoneVerified:    user.PhoneVerified,
		TwoFactorEnabled: user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}
}
