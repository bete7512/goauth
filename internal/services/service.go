package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
)

// AuthService implements the AuthService interface
type AuthService struct {
	Auth *config.Auth
}

// NewAuthService creates a new auth service
func NewAuthService(auth *config.Auth) interfaces.Service {
	return &AuthService{
		Auth: auth,
	}
}



// ResetPassword handles password reset
func (s *AuthService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) error {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Update user password and revoke reset token
	// This would require finding the user by token and updating their password

	return errors.New("not implemented")
}

// RegisterWithInvitation handles invitation-based registration
func (s *AuthService) RegisterWithInvitation(ctx context.Context, req *dto.RegisterWithInvitationRequest) (*dto.RegisterResponse, error) {
	// Check if user already exists
	existingUser, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// TODO: Validate invitation token
	// For now, we'll trust the invitation token from the frontend

	// Hash password
	hashedPassword, err := s.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	emailVerified := !s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup
	phoneVerified := !s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup
	twoFactorEnabled := false
	active := !(s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup || s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup)
	isAdmin := false

	user := &models.User{
		Email:            req.Email,
		Password:         hashedPassword,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		EmailVerified:    &emailVerified,
		PhoneVerified:    &phoneVerified,
		TwoFactorEnabled: &twoFactorEnabled,
		Active:           &active,
		IsAdmin:          &isAdmin,
		SignedUpVia:      "invitation",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save user
	if err := s.Auth.Repository.GetUserRepository().CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Revoke invitation token
	s.Auth.Repository.GetTokenRepository().RevokeAllTokens(ctx, req.Email, models.InvitationToken)

	// Generate tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Send welcome email
	if s.Auth.Config.Email.CustomSender != nil && s.Auth.Config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		if err := s.Auth.Config.Email.CustomSender.SendWelcomeEmail(ctx, *user); err != nil {
			s.Auth.Logger.Errorf("Failed to send welcome email: %v", err)
		}
	}

	return &dto.RegisterResponse{
		Message: "registration successful",
		User:    s.mapUserToDTO(user),
		Tokens: &dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}
