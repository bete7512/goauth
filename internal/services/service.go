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

// Register handles user registration
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error) {
	// Check if user already exists
	existingUser, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash password
	hashedPassword, err := s.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	emailVerified := false
	phoneVerified := false
	twoFactorEnabled := false
	active := true
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
		SignedUpVia:      "email",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save user
	if err := s.Auth.Repository.GetUserRepository().CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Send welcome email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendWelcomeEmail(ctx, *user); err != nil {
			s.Auth.Logger.Errorf("Failed to send welcome email: %v", err)
		}
	}

	return &dto.RegisterResponse{
		Message: "registration successful",
		User:    s.mapUserToDTO(user),
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// Login handles user authentication
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if user.Active != nil && !*user.Active {
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if err := s.Auth.TokenManager.ValidatePassword(user.Password, req.Password); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Generate tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		s.Auth.Logger.Errorf("Failed to update last login: %v", err)
	}

	return &dto.LoginResponse{
		Message: "login successful",
		User:    s.mapUserToDTO(user),
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// Logout handles user logout
func (s *AuthService) Logout(ctx context.Context, userID string) error {
	// Revoke all refresh tokens for the user

	return s.Auth.Repository.GetTokenRepository().RevokeAllTokens(ctx, userID, models.RefreshToken)
}

// RefreshToken handles token refresh
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshTokenResponse, error) {
	// Validate refresh token
	claims, err := s.Auth.TokenManager.ValidateJWTToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Get user
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Check if user is active
	if user.Active != nil && !*user.Active {
		return nil, errors.New("account is deactivated")
	}

	// Generate new tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Revoke old refresh token
	s.Auth.Repository.GetTokenRepository().RevokeAllTokens(ctx, userID, models.RefreshToken)

	return &dto.RefreshTokenResponse{
		Message: "token refreshed successfully",
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// ForgotPassword handles password reset request
func (s *AuthService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) error {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate reset token
	resetToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(resetToken)
	if err != nil {
		return fmt.Errorf("failed to hash reset token: %w", err)
	}

	// Save reset token (1 hour expiry)
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.PasswordResetToken, time.Hour); err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	// Create reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.Auth.Config.App.FrontendURL, resetToken)

	// Send reset email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendPasswordResetEmail(ctx, *user, resetURL); err != nil {
			return fmt.Errorf("failed to send reset email: %w", err)
		}
	}

	return nil
}

// ResetPassword handles password reset
func (s *AuthService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) error {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Update user password and revoke reset token
	// This would require finding the user by token and updating their password

	return errors.New("not implemented")
}

// SendMagicLink handles magic link request
func (s *AuthService) SendMagicLink(ctx context.Context, req *dto.MagicLinkRequest) error {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate magic link token
	magicToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate magic link token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(magicToken)
	if err != nil {
		return fmt.Errorf("failed to hash magic link token: %w", err)
	}

	// Save magic link token (15 minutes expiry)
	expiry := 15 * time.Minute
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.MakicLinkToken, expiry); err != nil {
		return fmt.Errorf("failed to save magic link token: %w", err)
	}

	// Create magic link URL
	magicURL := fmt.Sprintf("%s/verify-magic-link?token=%s", s.Auth.Config.App.FrontendURL, magicToken)

	// Send magic link email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendMagicLinkEmail(ctx, *user, magicURL); err != nil {
			return fmt.Errorf("failed to send magic link email: %w", err)
		}
	}

	return nil
}

// VerifyMagicLink handles magic link verification
func (s *AuthService) VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, error) {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Get user by token and generate login response
	// This would require finding the user by token

	return nil, errors.New("not implemented")
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
	emailVerified := true
	phoneVerified := false
	twoFactorEnabled := false
	active := true
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
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendWelcomeEmail(ctx, *user); err != nil {
			s.Auth.Logger.Errorf("Failed to send welcome email: %v", err)
		}
	}

	return &dto.RegisterResponse{
		Message: "registration successful",
		User:    s.mapUserToDTO(user),
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}
