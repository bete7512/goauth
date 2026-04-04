package core_services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// SendEmailVerification creates a verification token and emits an event for notification delivery.
func (s *coreService) SendEmailVerification(ctx context.Context, email string) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// Don't reveal if user exists
			return &dto.MessageResponse{Message: "If an account exists, a verification email has been sent"}, nil
		}
		return nil, types.NewInternalError("failed to find user by email").Wrap(err)
	}

	if user.EmailVerified {
		return &dto.MessageResponse{Message: "Email is already verified"}, nil
	}

	token, err := s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError("failed to generate token").Wrap(err)
	}

	verificationLink := s.buildVerificationLink(token)

	// FIXME: verification expiration time have to be set from configuration to override default one
	verificationToken := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		Token:     token,
		Type:      models.TokenTypeEmailVerification,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, verificationToken); err != nil {
		return nil, types.NewInternalError("failed to create verification token").Wrap(err)
	}

	s.Deps.Events.EmitAsync(ctx, types.EventSendEmailVerification, &types.EmailVerificationRequestData{
		User:             user,
		VerificationLink: verificationLink,
	})

	return &dto.MessageResponse{Message: "Verification email sent successfully"}, nil
}

// ResendEmailVerification deletes any existing token, creates a new one, and emits event.
func (s *coreService) ResendEmailVerification(ctx context.Context, email string) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return &dto.MessageResponse{Message: "If an account exists, a verification email has been sent"}, nil
		}
		return nil, types.NewInternalError("failed to find user by email").Wrap(err)
	}

	if user.EmailVerified {
		return &dto.MessageResponse{Message: "Email is already verified"}, nil
	}

	// Delete existing token if present
	existingToken, _ := s.TokenRepository.FindByEmailAndType(ctx, email, models.TokenTypeEmailVerification)
	if existingToken != nil {
		if err := s.TokenRepository.DeleteByIDAndType(ctx, existingToken.ID, models.TokenTypeEmailVerification); err != nil {
			return nil, types.NewInternalError("failed to delete existing verification token").Wrap(err)
		}
	}

	token, err := s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError("failed to generate token").Wrap(err)
	}

	verificationLink := s.buildVerificationLink(token)

	verificationToken := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		Token:     token,
		Type:      models.TokenTypeEmailVerification,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
		CreatedAt: time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, verificationToken); err != nil {
		return nil, types.NewInternalError("failed to create verification token").Wrap(err)
	}

	s.Deps.Events.EmitAsync(ctx, types.EventSendEmailVerification, &types.EmailVerificationRequestData{
		User:             user,
		VerificationLink: verificationLink,
	})

	return &dto.MessageResponse{Message: "Verification will be email resent"}, nil
}

// SendPhoneVerification creates an OTP and emits an event for notification delivery.
func (s *coreService) SendPhoneVerification(ctx context.Context, phone string) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByPhoneNumber(ctx, phone)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return &dto.MessageResponse{Message: "If an account exists, a verification SMS has been sent"}, nil
		}
		return nil, types.NewInternalError("failed to find user by phone").Wrap(err)
	}

	if user.PhoneNumberVerified {
		return &dto.MessageResponse{Message: "Phone number is already verified"}, nil
	}

	code, err := s.Deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, types.NewInternalError("failed to generate OTP").Wrap(err)
	}

	verificationToken := &models.Token{
		ID:          uuid.Must(uuid.NewV7()).String(),
		UserID:      user.ID,
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		PhoneNumber: phone,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, verificationToken); err != nil {
		return nil, types.NewInternalError("failed to create verification token").Wrap(err)
	}

	s.Deps.Events.EmitAsync(ctx, types.EventSendPhoneVerification, &types.PhoneVerificationRequestData{
		User:       user,
		Code:       code,
		ExpiryTime: "15 minutes",
	})

	return &dto.MessageResponse{Message: "Verification SMS sent successfully"}, nil
}

// ResendPhoneVerification deletes any existing token, creates a new one, and emits event.
func (s *coreService) ResendPhoneVerification(ctx context.Context, phone string) (*dto.MessageResponse, *types.GoAuthError) {
	user, err := s.UserRepository.FindByPhoneNumber(ctx, phone)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return &dto.MessageResponse{Message: "If an account exists, a verification SMS has been sent"}, nil
		}
		return nil, types.NewInternalError("failed to find user by phone").Wrap(err)
	}

	if user.PhoneNumberVerified {
		return &dto.MessageResponse{Message: "Phone number is already verified"}, nil
	}

	// Delete existing token if present
	existingToken, _ := s.TokenRepository.FindByPhoneAndType(ctx, phone, models.TokenTypePhoneVerification)
	if existingToken != nil {
		if err := s.TokenRepository.DeleteByIDAndType(ctx, existingToken.ID, models.TokenTypePhoneVerification); err != nil {
			return nil, types.NewInternalError("failed to delete existing verification token").Wrap(err)
		}
	}

	code, err := s.Deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, types.NewInternalError("failed to generate OTP").Wrap(err)
	}

	verificationToken := &models.Token{
		ID:          uuid.Must(uuid.NewV7()).String(),
		UserID:      user.ID,
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		PhoneNumber: phone,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Used:        false,
		CreatedAt:   time.Now(),
	}

	if err := s.TokenRepository.Create(ctx, verificationToken); err != nil {
		return nil, types.NewInternalError("failed to create verification token").Wrap(err)
	}

	s.Deps.Events.EmitAsync(ctx, types.EventSendPhoneVerification, &types.PhoneVerificationRequestData{
		User:       user,
		Code:       code,
		ExpiryTime: "15 minutes",
	})

	return &dto.MessageResponse{Message: "Verification SMS resent successfully"}, nil
}

// VerifyEmail validates a token, marks the user's email as verified, and emits EventAfterEmailVerified.
func (s *coreService) VerifyEmail(ctx context.Context, token string) (*dto.MessageResponse, *types.GoAuthError) {
	verification, err := s.TokenRepository.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid verification token", 400)
		}
		return nil, types.NewInternalError("failed to find verification token").Wrap(err)
	}

	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewGoAuthError(types.ErrTokenExpired, "verification token has expired", 400)
	}

	if verification.Used {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "verification token has already been used", 400)
	}

	if verification.Type != models.TokenTypeEmailVerification {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid token type", 400)
	}

	user, err := s.UserRepository.FindByEmail(ctx, verification.Email)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user by email").Wrap(err)
	}

	now := time.Now()
	user.EmailVerified = true
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError("failed to update user").Wrap(err)
	}

	if err := s.TokenRepository.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, types.NewInternalError("failed to mark token as used").Wrap(err)
	}

	// Emit event so notification can send welcome email
	s.Deps.Events.EmitAsync(ctx, types.EventAfterEmailVerified, &types.UserEventData{
		User: user,
	})

	return &dto.MessageResponse{Message: "Email verified successfully"}, nil
}

// VerifyPhone validates an OTP code, marks the user's phone as verified.
func (s *coreService) VerifyPhone(ctx context.Context, code string, phone string) (*dto.MessageResponse, *types.GoAuthError) {
	verification, err := s.TokenRepository.FindByCode(ctx, code, models.TokenTypePhoneVerification)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid verification code", 400)
		}
		return nil, types.NewInternalError("failed to find verification code").Wrap(err)
	}

	if verification.PhoneNumber != phone {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "code does not match phone number", 400)
	}

	if verification.ExpiresAt.Before(time.Now()) {
		return nil, types.NewGoAuthError(types.ErrTokenExpired, "verification code has expired", 400)
	}

	if verification.Used {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "verification code has already been used", 400)
	}

	if err := s.TokenRepository.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, types.NewInternalError("failed to mark code as used").Wrap(err)
	}

	user, err := s.UserRepository.FindByPhoneNumber(ctx, verification.PhoneNumber)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user by phone").Wrap(err)
	}

	now := time.Now()
	user.PhoneNumberVerified = true
	user.UpdatedAt = &now

	if err := s.UserRepository.Update(ctx, user); err != nil {
		return nil, types.NewInternalError("failed to update user").Wrap(err)
	}

	return &dto.MessageResponse{Message: "Phone verified successfully"}, nil
}

// buildVerificationLink builds a verification link that points to the backend verify-email endpoint.
// The backend verifies the token and redirects to the frontend callback path.
func (s *coreService) buildVerificationLink(token string) string {
	if s.Deps.Config.APIURL == "" {
		return ""
	}
	apiURL := s.Deps.Config.APIURL + s.Deps.Config.BasePath
	return fmt.Sprintf("%s/verify-email?token=%s", apiURL, token)
}

// buildPasswordResetLink builds a password reset link using frontend config.
func (s *coreService) buildPasswordResetLink(token string) string {
	if s.Deps.Config.FrontendConfig == nil || s.Deps.Config.FrontendConfig.ResetPasswordPath == "" {
		return ""
	}
	baseURL := s.Deps.Config.FrontendConfig.URL
	if baseURL == "" {
		return ""
	}
	resetPath := s.Deps.Config.FrontendConfig.ResetPasswordPath
	return fmt.Sprintf("%s%s?token=%s", baseURL, resetPath, token)
}
