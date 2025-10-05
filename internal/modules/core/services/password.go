package core_services

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ForgotPassword initiates password reset process
func (s *CoreService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) (*dto.MessageResponse, error) {
	var user *models.User
	var err error

	// Find user by email or phone
	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else if req.Phone != "" {
		user, err = s.UserRepository.FindByPhone(ctx, req.Phone)
	} else {
		return nil, errors.New("email or phone is required")
	}

	if err != nil || user == nil {
		// Don't reveal if user exists for security
		return &dto.MessageResponse{
			Message: "If an account exists, password reset instructions have been sent",
			Success: true,
		}, nil
	}

	if !user.Active {
		return nil, errors.New("account is inactive")
	}

	// Generate token or code based on method
	var token string
	var code string

	if req.Email != "" {
		// Email: generate token
		token, err = generateSecureToken(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %w", err)
		}
	} else {
		// Phone: generate 6-digit code
		code = fmt.Sprintf("%06d", rand.Intn(1000000))
	}

	// Create password reset record
	resetToken := &models.Token{
		ID:     uuid.New().String(),
		UserID: user.ID,
		Token:  token,
		// Code:      code,
		Type:      "password_reset",
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		CreatedAt: time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, resetToken); err != nil {
		return nil, fmt.Errorf("failed to create reset token: %w", err)
	}

	// Emit event to send email/SMS
	if req.Email != "" {
		s.deps.Events.Emit(ctx, "password:reset:request", map[string]interface{}{
			"user_id":     user.ID,
			"email":       user.Email,
			"name":        user.Name,
			"reset_token": token,
		})
	} else {
		s.deps.Events.Emit(ctx, "password:reset:sms", map[string]interface{}{
			"user_id":    user.ID,
			"phone":      user.Phone,
			"reset_code": code,
		})
	}

	return &dto.MessageResponse{
		Message: "If an account exists, password reset instructions have been sent",
		Success: true,
	}, nil
}

// ResetPassword resets password using token/code
func (s *CoreService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) (*dto.MessageResponse, error) {
	var resetToken *models.Token
	var err error
	// Find reset token
	if req.Token != "" {
		resetToken, err = s.TokenRepository.FindByToken(ctx, req.Token)
		if err != nil {
			return nil, errors.New("invalid or expired reset token")
		}
	} else if req.Code != "" {
		resetToken, err = s.TokenRepository.FindByToken(ctx, req.Code)
		if err != nil {
			return nil, errors.New("invalid or expired reset code")
		}
	} else {
		return nil, errors.New("reset token or code is required")
	}

	// Check if token expired
	if resetToken.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("reset token expired")
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, resetToken.UserID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Delete reset token
	s.TokenRepository.Delete(ctx, resetToken.ID)

	// Invalidate all sessions for security
	s.SessionRepository.DeleteByUserID(ctx, user.ID)

	// Emit event
	s.deps.Events.Emit(ctx, "password:changed", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return &dto.MessageResponse{
		Message: "Password reset successfully. Please login with your new password.",
		Success: true,
	}, nil
}

// ChangePassword changes password (requires old password)
func (s *CoreService) ChangePassword(ctx context.Context, userID string, req *dto.ChangePasswordRequest) (*dto.MessageResponse, error) {
	// Find user
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		return nil, errors.New("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Emit event
	s.deps.Events.Emit(ctx, "password:changed", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return &dto.MessageResponse{
		Message: "Password changed successfully",
		Success: true,
	}, nil
}


