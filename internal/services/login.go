package services

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
)

// Login handles user authentication
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	// Get user by email
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		if err != nil {
			s.Auth.Logger.Errorf("Failed to get user by email: %v", err)
			return nil, errors.New("internal server error")
		}
		return nil, errors.New("user not found")
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
		s.Auth.Logger.Errorf("Failed to generate tokens: %v", err)
		return nil, errors.New("failed to generate tokens")
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		s.Auth.Logger.Errorf("Failed to update last login: %v", err)
		return nil, errors.New("failed to update last login")
	}
 
	// Cache user
	if err := s.Auth.Cache.Set(ctx, "user:"+user.ID, user, s.Auth.Config.AuthConfig.JWT.AccessTokenTTL); err != nil {
		s.Auth.Logger.Errorf("Failed to cache user: %v", err)
		return nil, errors.New("failed to cache user")
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
func (s *AuthService) Logout(ctx context.Context, userID string, sessionID string) error {
	if s.Auth.Config.AuthConfig.Methods.EnableMultiSession {
		session, err := s.Auth.Repository.GetSessionRepository().GetSessionBySessionID(ctx, sessionID)
		if err != nil {
			s.Auth.Logger.Errorf("Failed to get session: %v", err)
			return errors.New("failed to get session")
		}
		if session != nil {
			err = s.Auth.Repository.GetSessionRepository().DeleteSession(ctx, session)
			if err != nil {
				s.Auth.Logger.Errorf("Failed to delete session: %v", err)
				return errors.New("failed to delete session")
			}
			return nil
		}
	}
	sessions, err := s.Auth.Repository.GetSessionRepository().GetSessionByUserID(ctx, userID)
	if err != nil {
		s.Auth.Logger.Errorf("Failed to get session: %v", err)
		return errors.New("failed to get session")
	}
	if len(sessions) < 0 {
		return nil
	}
	err = s.Auth.Repository.GetSessionRepository().DeleteAllUserSessions(ctx, userID)
	if err != nil {
		s.Auth.Logger.Errorf("Failed to delete all user sessions: %v", err)
		return errors.New("failed to delete all user sessions")
	}
	return nil
}
