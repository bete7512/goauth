package core_services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Login authenticates user and creates session
func (s *CoreService) Login(ctx context.Context, req *dto.LoginRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	var user *models.User
	var err error
	user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}
	if s.Config.RequireEmailVerification && user.Email != "" && user.EmailVerified {
		return dto.AuthResponse{}, types.NewEmailNotVerifiedError()
	}
	if s.Config.RequirePhoneVerification && user.PhoneNumber != "" && user.PhoneNumberVerified {
		return dto.AuthResponse{}, types.NewPhoneNotVerifiedError()
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	accessToken, refreshToken, err := s.SecurityManager.GenerateTokens(user, map[string]interface{}{})
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate tokens: %s", err.Error()))
	}

	// Create session
	session := &models.Session{
		ID:                    uuid.New().String(),
		UserID:                user.ID,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(s.Deps.Config.Security.Session.SessionTTL), // 24 hours
		CreatedAt:             time.Now(),
	}
	now := time.Now()

	user.LastLoginAt = &now
	if err := s.UserRepository.Update(ctx, user); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to update user: %s", err.Error()))
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to create session: %s", err.Error()))
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User: &dto.UserDTO{
			ID:                  user.ID,
			Email:               user.Email,
			Username:            user.Username,
			Name:                user.Name,
			FirstName:           user.FirstName,
			LastName:            user.LastName,
			PhoneNumber:         user.PhoneNumber,
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
		},
		ExpiresIn: int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:   "Login successful",
	}, nil
}
