package core_services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Signup creates a new user account
func (s *CoreService) Signup(ctx context.Context, req *dto.SignupRequest) (*dto.AuthResponse, error) {
	// Check if user already exists
	if req.Email != "" {
		existing, _ := s.UserRepository.FindByEmail(ctx, req.Email)
		if existing != nil {
			return nil, errors.New("user with this email already exists")
		}
	}

	if req.Username != "" {
		existing, _ := s.UserRepository.FindByUsername(ctx, req.Username)
		if existing != nil {
			return nil, errors.New("user with this username already exists")
		}
	}

	if req.Phone != "" {
		existing, _ := s.UserRepository.FindByPhone(ctx, req.Phone)
		if existing != nil {
			return nil, errors.New("user with this phone already exists")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		Phone:        req.Phone,
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.UserRepository.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate session token
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours
		CreatedAt: time.Now(),
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Emit after:signup event
	s.deps.Events.Emit(ctx, "after:signup", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
	})

	return &dto.AuthResponse{
		Token: sessionToken,
		User: &dto.UserDTO{
			ID:            user.ID,
			Email:         user.Email,
			Username:      user.Username,
			Name:          user.Name,
			Phone:         user.Phone,
			Active:        user.Active,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			CreatedAt:     user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
		},
		ExpiresIn: 86400, // 24 hours in seconds
		Message:   "Signup successful",
	}, nil
}

// Login authenticates user and creates session
func (s *CoreService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.AuthResponse, error) {
	// Find user
	var user *models.User
	var err error

	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else if req.Username != "" {
		user, err = s.UserRepository.FindByUsername(ctx, req.Username)
	} else {
		return nil, errors.New("email or username is required")
	}

	if err != nil || user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if account is active
	if !user.Active {
		return nil, errors.New("account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Generate session token
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create session
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours
		CreatedAt: time.Now(),
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	user.UpdatedAt = time.Now()
	s.UserRepository.Update(ctx, user)

	// Emit after:login event
	s.deps.Events.Emit(ctx, "after:login", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return &dto.AuthResponse{
		Token: sessionToken,
		User: &dto.UserDTO{
			ID:            user.ID,
			Email:         user.Email,
			Username:      user.Username,
			Name:          user.Name,
			Phone:         user.Phone,
			Active:        user.Active,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			CreatedAt:     user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
		},
		ExpiresIn: 86400, // 24 hours in seconds
		Message:   "Login successful",
	}, nil
}

// Logout invalidates user session
func (s *CoreService) Logout(ctx context.Context, sessionToken string) error {
	session, err := s.SessionRepository.FindByToken(ctx, sessionToken)
	if err != nil || session == nil {
		return errors.New("invalid session")
	}

	if err := s.SessionRepository.Delete(ctx, session.ID); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Emit after:logout event
	s.deps.Events.Emit(ctx, "after:logout", map[string]interface{}{
		"user_id": session.UserID,
	})

	return nil
}

// GetCurrentUser retrieves user from session token
func (s *CoreService) GetCurrentUser(ctx context.Context, sessionToken string) (*dto.UserDTO, error) {
	session, err := s.SessionRepository.FindByToken(ctx, sessionToken)
	if err != nil || session == nil {
		return nil, errors.New("invalid session")
	}

	// Check if session expired
	if session.ExpiresAt.Before(time.Now()) {
		s.SessionRepository.Delete(ctx, session.ID)
		return nil, errors.New("session expired")
	}

	user, err := s.UserRepository.FindByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.UserDTO{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		Name:          user.Name,
		Phone:         user.Phone,
		Avatar:        user.Avatar,
		Active:        user.Active,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// Helper function to generate secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
