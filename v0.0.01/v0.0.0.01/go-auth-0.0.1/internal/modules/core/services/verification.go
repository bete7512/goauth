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
)

// SendVerificationEmail sends email verification token
func (s *CoreService) SendVerificationEmail(ctx context.Context, req *dto.SendVerificationEmailRequest) (*dto.MessageResponse, error) {
	user, err := s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	if user.EmailVerified {
		return nil, errors.New("email already verified")
	}

	// Generate verification token
	token, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
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

	if err := s.deps.Storage.Create(ctx, verification); err != nil {
		return nil, fmt.Errorf("failed to create verification: %w", err)
	}

	// Emit event to send email
	err = s.deps.Events.Emit(ctx, "email:verification:sent", map[string]interface{}{
		"user_id":            user.ID,
		"email":              user.Email,
		"name":               user.Name,
		"verification_token": token,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to emit event: %w", err)
	}

	return &dto.MessageResponse{
		Message: "Verification email sent successfully",
		Success: true,
	}, nil
}

// VerifyEmail verifies email with token
func (s *CoreService) VerifyEmail(ctx context.Context, req *dto.VerifyEmailRequest) (*dto.MessageResponse, error) {
	// Find verification token
	var verification models.VerificationToken
	if err := s.deps.Storage.FindOne(ctx, &verification, "token = ? AND email = ? AND type = ?", req.Token, req.Email, "email"); err != nil {
		return nil, errors.New("invalid or expired verification token")
	}

	// Check if token expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("verification token expired")
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Update user
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Delete verification token
	s.deps.Storage.Delete(ctx, &verification)

	// Emit event
	s.deps.Events.Emit(ctx, "email:verified", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return &dto.MessageResponse{
		Message: "Email verified successfully",
		Success: true,
	}, nil
}

// SendVerificationPhone sends phone verification code
func (s *CoreService) SendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, error) {
	user, err := s.UserRepository.FindByPhone(ctx, req.Phone)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	if user.PhoneVerified {
		return nil, errors.New("phone already verified")
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

	if err := s.deps.Storage.Create(ctx, verification); err != nil {
		return nil, fmt.Errorf("failed to create verification: %w", err)
	}

	// Emit event to send SMS
	s.deps.Events.Emit(ctx, "phone:verification:sent", map[string]interface{}{
		"user_id": user.ID,
		"phone":   user.Phone,
		"code":    code,
	})

	return &dto.MessageResponse{
		Message: "Verification code sent to your phone",
		Success: true,
	}, nil
}

// VerifyPhone verifies phone with code
func (s *CoreService) VerifyPhone(ctx context.Context, req *dto.VerifyPhoneRequest) (*dto.MessageResponse, error) {
	// Find verification code
	var verification models.VerificationToken
	if err := s.deps.Storage.FindOne(ctx, &verification, "code = ? AND phone = ? AND type = ?", req.Code, req.Phone, "phone"); err != nil {
		return nil, errors.New("invalid or expired verification code")
	}

	// Check if code expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("verification code expired")
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Update user
	user.PhoneVerified = true
	user.UpdatedAt = time.Now()

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Delete verification code
	s.deps.Storage.Delete(ctx, &verification)

	// Emit event
	s.deps.Events.Emit(ctx, "phone:verified", map[string]interface{}{
		"user_id": user.ID,
		"phone":   user.Phone,
	})

	return &dto.MessageResponse{
		Message: "Phone verified successfully",
		Success: true,
	}, nil
}

// ResendVerificationEmail resends email verification
func (s *CoreService) ResendVerificationEmail(ctx context.Context, req *dto.SendVerificationEmailRequest) (*dto.MessageResponse, error) {
	// Delete old verification tokens for this email
	s.deps.Storage.DeleteWhere(ctx, &models.VerificationToken{}, "email = ? AND type = ?", req.Email, "email")

	// Send new verification
	return s.SendVerificationEmail(ctx, req)
}

// ResendVerificationPhone resends phone verification
func (s *CoreService) ResendVerificationPhone(ctx context.Context, req *dto.SendVerificationPhoneRequest) (*dto.MessageResponse, error) {
	// Delete old verification codes for this phone
	s.deps.Storage.DeleteWhere(ctx, &models.VerificationToken{}, "phone = ? AND type = ?", req.Phone, "phone")

	// Send new verification
	return s.SendVerificationPhone(ctx, req)
}
