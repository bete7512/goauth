package core_services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ForgotPassword initiates password reset process
func (s *CoreService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var user *models.User
	var err error

	// Find user by email or phone
	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "email is required", 400)
	}

	if err != nil || user == nil {
		// Don't reveal if user exists for security
		return &dto.MessageResponse{
			Message: "If an account exists, password reset instructions have been sent",
			Success: true,
		}, nil
	}

	// Generate token or code based on method
	var token string

	if req.Email != "" {
		// Email: generate token
		token, err = s.Deps.SecurityManager.GenerateRandomToken(32)
		if err != nil {
			return nil, types.NewInternalError(fmt.Sprintf("failed to generate token: %v", err))
		}
	}

	// Create password reset record
	resetToken := &models.Token{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		Type:      "password_reset",
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		CreatedAt: time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, resetToken); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create reset token: %v", err))
	}

	// Build reset link
	resetLink := fmt.Sprintf("https://yourapp.com/reset-password?token=%s", token)

	// Emit event for notification module
	s.Deps.Events.EmitAsync(ctx, types.EventBeforeResetPassword, &types.PasswordResetRequestData{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		ResetLink: resetLink,
		Code:      token[:6], // First 6 chars as code
	})

	return &dto.MessageResponse{
		Message: "If an account exists, password reset instructions have been sent",
		Success: true,
	}, nil
}

// ResetPassword resets password using token/code
func (s *CoreService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var resetToken *models.Token
	var err error

	// Find reset token
	if req.Token != "" {
		resetToken, err = s.TokenRepository.FindByToken(ctx, req.Token)
		if err != nil {
			return nil, types.NewInvalidTokenError()
		}
	} else if req.Code != "" {
		resetToken, err = s.TokenRepository.FindByToken(ctx, req.Code)
		if err != nil {
			return nil, types.NewInvalidTokenError()
		}
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "reset token or code is required", 400)
	}

	// Check if token expired
	if resetToken.ExpiresAt.Before(time.Now()) {
		return nil, types.NewTokenExpiredError()
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, resetToken.UserID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	now := time.Now()
	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err))
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update password: %v", err))
	}

	// Delete reset token
	s.TokenRepository.Delete(ctx, resetToken.ID)

	// Note: Session invalidation is now handled by the auth modules (session or stateless)
	// For security, users should re-login after password reset

	// Emit event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterResetPassword, &types.PasswordChangedData{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Timestamp: time.Now(),
	})

	return &dto.MessageResponse{
		Message: "Password reset successfully. Please login with your new password.",
		Success: true,
	}, nil
}

// ChangePassword changes password (requires old password)
func (s *CoreService) ChangePassword(ctx context.Context, userID string, req *dto.ChangePasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Find user
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	now := time.Now()
	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		return nil, types.NewInvalidCredentialsError()
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err))
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update password: %v", err))
	}

	// Emit event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterChangePassword, &types.PasswordChangedData{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Timestamp: time.Now(),
	})

	return &dto.MessageResponse{
		Message: "Password changed successfully",
		Success: true,
	}, nil
}
