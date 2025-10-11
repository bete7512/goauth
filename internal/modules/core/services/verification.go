package core_services

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// SendVerificationEmail sends email verification token
func (s *CoreService) SendVerificationEmail(ctx context.Context, req *dto.SendVerificationEmailRequest) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}
	if user.EmailVerified {
		return nil, types.NewEmailAlreadyVerifiedError()
	}

	// Generate verification token
	token, err := s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate token: %v", err))
	}

	// Create verification record
	verification := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     req.Email,
		Token:     token,
		Type:      "email",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := s.VerificationTokenRepository.Create(ctx, verification); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create verification: %v", err))
	}

	// Build verification link (you can customize this based on your frontend URL)
	verificationLink := fmt.Sprintf("https://yourapp.com/verify-email?token=%s", token)

	// Emit generic event to send email (preferred)
	s.Deps.Events.EmitAsync(ctx, types.EventSendEmailVerification, map[string]interface{}{
		"user_id":           user.ID,
		"email":             user.Email,
		"name":              user.Name,
		"verification_link": verificationLink,
		"code":              token[:6], // First 6 chars as a code option
	})

	return &dto.MessageResponse{
		Message: "Verification email sent successfully",
		Success: true,
	}, nil
}

// VerifyEmail verifies email with token
func (s *CoreService) VerifyEmail(ctx context.Context, req *dto.VerifyEmailRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Find verification token
	var verification *models.VerificationToken
	var err error
	if verification, err = s.VerificationTokenRepository.FindByToken(ctx, req.Token); err != nil {
		return nil, types.NewInvalidVerificationTokenError()
	}

	// Check if token expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewVerificationTokenExpiredError()
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	user.EmailVerified = true
	user.UpdatedAt = time.Now()
	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update user: %w", err))
	}

	// Delete verification token
	s.VerificationTokenRepository.Delete(ctx, verification.ID, string(models.TokenTypeEmailVerification))

	// Emit event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterChangeEmailVerification, map[string]interface{}{
		"user":  user,
		"email": user.Email,
		"name":  user.Name,
	})

	return &dto.MessageResponse{
		Message: "Email verified successfully",
		Success: true,
	}, nil
}

// SendVerificationPhone sends phone verification code
func (s *CoreService) SendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var user *models.User
	var err error
	if user, err = s.UserRepository.FindByID(ctx, req.Phone); err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}
	if user.PhoneNumberVerified {
		return nil, types.NewPhoneAlreadyVerifiedError()
	}

	// Generate 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Create verification record
	verification := &models.VerificationToken{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		PhoneNumber: req.Phone,
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	if err := s.VerificationTokenRepository.Create(ctx, verification); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create verification: %w", err))
	}

	// Emit generic event to send SMS (preferred)
	s.Deps.Events.EmitAsync(ctx, types.EventSendPhoneVerification, map[string]interface{}{
		"user":         user,
		"email":        user.Email,
		"phone_number": req.Phone,
		"code":         code,
	})

	return &dto.MessageResponse{
		Message: "Verification code sent to your phone",
		Success: true,
	}, nil
}

// VerifyPhone verifies phone with code
func (s *CoreService) VerifyPhone(ctx context.Context, req *dto.VerifyPhoneRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Find verification code
	var verification *models.VerificationToken
	var err error
	if verification, err = s.VerificationTokenRepository.FindByCode(ctx, req.Code, string(models.TokenTypePhoneVerification)); err != nil {
		return nil, types.NewInvalidVerificationCodeError()
	}

	// Check if code expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewVerificationCodeExpiredError()
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	// Mark phone verified
	user.PhoneNumberVerified = true
	user.UpdatedAt = time.Now()
	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update user: %w", err))
	}

	// Delete verification code
	s.VerificationTokenRepository.Delete(ctx, verification.ID, string(models.TokenTypePhoneVerification))

	// Emit event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterChangePhoneVerification, map[string]interface{}{
		"user":  user,
		"phone": req.Phone,
		"name":  user.Name,
	})

	return &dto.MessageResponse{
		Message: "Phone verified successfully",
		Success: true,
	}, nil
}

// ResendVerificationEmail resends email verification
func (s *CoreService) ResendVerificationEmail(ctx context.Context, req *dto.SendVerificationEmailRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Delete old verification tokens for this email
	s.VerificationTokenRepository.Delete(ctx, req.Email, string(models.TokenTypeEmailVerification))

	// Send new verification
	return s.SendVerificationEmail(ctx, req)
}

// ResendVerificationPhone resends phone verification
func (s *CoreService) ResendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Delete old verification codes for this phone
	s.VerificationTokenRepository.Delete(ctx, req.Phone, string(models.TokenTypePhoneVerification))

	// Send new verification
	return s.SendVerificationPhone(ctx, req)
}
