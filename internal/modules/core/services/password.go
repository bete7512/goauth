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

// ForgotPassword initiates password reset process.
func (s *coreService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var user *models.User
	var err error

	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else if req.Phone != "" {
		user, err = s.UserRepository.FindByPhoneNumber(ctx, req.Phone)
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "email or phone is required", 400)
	}

	if err != nil || user == nil {
		// Don't reveal if user exists for security
		return &dto.MessageResponse{
			Message: "If an account exists, password reset instructions have been sent",
		}, nil
	}

	// Generate token and OTP code
	token, err := s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate token: %v", err))
	}

	code, err := s.Deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate OTP: %v", err))
	}

	resetLink := s.buildPasswordResetLink(user.Email, token)

	// Create password reset token
	verificationToken := &models.Token{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Token:       token,
		Code:        code,
		Type:        models.TokenTypePasswordReset,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Used:        false,
		CreatedAt:   time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, verificationToken); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create reset token: %v", err))
	}

	// Emit event for notification delivery
	s.Deps.Events.EmitAsync(ctx, types.EventSendPasswordResetEmail, &types.PasswordResetRequestData{
		UserID:      user.ID,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		Name:        user.Name,
		ResetLink:   resetLink,
		Code:        code,
	})

	return &dto.MessageResponse{
		Message: "If an account exists, password reset instructions have been sent",
	}, nil
}

// ResetPassword resets password using token or code.
func (s *coreService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var verification *models.Token
	var err error

	// Find reset token
	if req.Token != "" {
		verification, err = s.TokenRepository.FindByToken(ctx, req.Token)
		if err != nil {
			return nil, types.NewInvalidTokenError()
		}
	} else if req.Code != "" {
		verification, err = s.TokenRepository.FindByCode(ctx, req.Code, models.TokenTypePasswordReset)
		if err != nil {
			return nil, types.NewInvalidTokenError()
		}
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "reset token or code is required", 400)
	}

	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewTokenExpiredError()
	}

	if verification.Used {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "reset token has already been used", 400)
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	now := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err))
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update password: %v", err))
	}

	// Mark token as used instead of deleting
	s.TokenRepository.MarkAsUsed(ctx, verification.ID)

	// Emit event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterResetPassword, &types.PasswordChangedData{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Timestamp: time.Now(),
	})

	return &dto.MessageResponse{
		Message: "Password reset successfully. Please login with your new password.",
	}, nil
}

// ChangePassword changes password (requires old password)
func (s *coreService) ChangePassword(ctx context.Context, userID string, req *dto.ChangePasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	now := time.Now()
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		return nil, types.NewInvalidCredentialsError()
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err))
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update password: %v", err))
	}

	s.Deps.Events.EmitAsync(ctx, types.EventAfterChangePassword, &types.PasswordChangedData{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Timestamp: time.Now(),
	})

	return &dto.MessageResponse{
		Message: "Password changed successfully",
	}, nil
}
