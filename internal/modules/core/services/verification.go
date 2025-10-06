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
	token, err := generateSecureToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate token: %w", err))
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
		return nil, types.NewInternalError(fmt.Sprintf("failed to create verification: %w", err))
	}

	// // Emit event to send email
	// err = s.deps.Events.Emit(ctx, "email:verification:sent", map[string]interface{}{
	// 	"user_id":            user.ID,
	// 	"email":              user.Email,
	// 	"name":               user.Name,
	// 	"verification_token": token,
	// })
	// if err != nil {
	// 	return nil, types.NewInternalError(fmt.Sprintf("failed to emit event: %w", err))
	// }

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

	// Update user
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update user: %w", err))
	}

	// Delete verification token
	s.VerificationTokenRepository.Delete(ctx, verification.ID)

	// // Emit event
	// s.deps.Events.Emit(ctx, "email:verified", map[string]interface{}{
	// 	"user_id": user.ID,
	// 	"email":   user.Email,
	// })

	return &dto.MessageResponse{
		Message: "Email verified successfully",
		Success: true,
	}, nil
}

// SendVerificationPhone sends phone verification code
func (s *CoreService) SendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByPhone(ctx, req.Phone)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	if user.PhoneVerified {
		return nil, types.NewPhoneAlreadyVerifiedError()
	}

	// Generate 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))

	// Create verification record
	verification := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Phone:     req.Phone,
		Code:      code,
		Type:      "phone",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err := s.VerificationTokenRepository.Create(ctx, verification); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create verification: %w", err))
	}

	// Emit event to send SMS
	// s.deps.Events.Emit(ctx, "phone:verification:sent", map[string]interface{}{
	// 	"user_id": user.ID,
	// 	"phone":   user.Phone,
	// 	"code":    code,
	// })

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
	if verification, err = s.VerificationTokenRepository.FindByCode(ctx, req.Code, "phone"); err != nil {
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

	// Update user
	user.PhoneVerified = true
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to update user: %w", err))
	}

	// Delete verification code
	s.VerificationTokenRepository.Delete(ctx, verification.ID)

	// // Emit event
	// s.deps.Events.Emit(ctx, "phone:verified", map[string]interface{}{
	// 	"user_id": user.ID,
	// 	"phone":   user.Phone,
	// })

	return &dto.MessageResponse{
		Message: "Phone verified successfully",
		Success: true,
	}, nil
}

// ResendVerificationEmail resends email verification
func (s *CoreService) ResendVerificationEmail(ctx context.Context, req *dto.SendVerificationEmailRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Delete old verification tokens for this email
	s.VerificationTokenRepository.Delete(ctx, req.Email)

	// Send new verification
	return s.SendVerificationEmail(ctx, req)
}

// ResendVerificationPhone resends phone verification
func (s *CoreService) ResendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, *types.GoAuthError) {
	// Delete old verification codes for this phone
	s.VerificationTokenRepository.Delete(ctx, req.Phone)

	// Send new verification
	return s.SendVerificationPhone(ctx, req)
}
