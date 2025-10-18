package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/google/uuid"
)

// SendEmailVerificationWithToken sends email verification and creates a token
func (s *NotificationService) SendEmailVerification(ctx context.Context, email string) error {

	// Generate verification token and code
	token, err := s.deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Build verification link
	verificationLink := s.buildVerificationLink(email, token)
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	// Create verification token record
	verificationToken := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		Type:      models.TokenTypeEmailVerification,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours expiry
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: created verification token for email %s", email)

	// Send email verification
	return s.sendEmailVerification(ctx, email, "", verificationLink)
}

// SendPhoneVerificationWithToken sends phone verification and creates a token
func (s *NotificationService) SendPhoneVerification(ctx context.Context, phoneNumber string) error {

	// Generate verification code (6-digit for phone)
	code, err := s.deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate numeric OTP: %w", err)
	}

	user, err := s.userRepo.FindByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	// Create verification token record
	verificationToken := &models.VerificationToken{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		PhoneNumber: phoneNumber,
		ExpiresAt:   time.Now().Add(15 * time.Minute), // 15 minutes expiry for phone
		Used:        false,
		CreatedAt:   time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: created phone verification token for phone number %s", phoneNumber)

	return s.sendPhoneVerification(ctx, *user, code, "15 minutes")
}

// ResendEmailVerification resends email verification
func (s *NotificationService) ResendEmailVerification(ctx context.Context, email string) error {

	// Find existing verification token
	existingToken, err := s.verificationTokenRepo.FindByEmailAndType(ctx, email, string(models.TokenTypeEmailVerification))
	if err == nil && existingToken != nil {
		s.verificationTokenRepo.Delete(ctx, existingToken.ID, string(models.TokenTypeEmailVerification))
	}

	// Generate new token and code
	token, err := s.deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Build verification link
	verificationLink := s.buildVerificationLink(email, token)

	// Create new verification token record
	verificationToken := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    existingToken.UserID,
		Token:     token,
		Type:      models.TokenTypeEmailVerification,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours expiry
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: resent verification email to %s", email)

	return s.sendEmailVerification(ctx, existingToken.Email, "", verificationLink)
}

func (s *NotificationService) SendPasswordResetEmail(ctx context.Context, email string) error {

	// Generate verification token and code
	token, err := s.deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	code, err := s.deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate numeric OTP: %w", err)
	}
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	resetLink := s.buildPasswordResetLink(email, token)

	// Create password reset token record
	passwordResetToken := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		Code:      code,
		Type:      models.TokenTypePasswordReset,
		Email:     email,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Store password reset token
	if err := s.verificationTokenRepo.Create(ctx, passwordResetToken); err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	s.deps.Logger.Infof("notification: created password reset token for %s", email)

	// Send password reset email
	return s.sendPasswordResetEmail(ctx, email, "", resetLink, code, "1 hour")
}

func (s *NotificationService) SendPasswordResetSMS(ctx context.Context, phoneNumber string) error {

	// Generate verification code (6-digit for phone)
	code, err := s.deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate numeric OTP: %w", err)
	}

	user, err := s.userRepo.FindByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	return s.sendPasswordResetSMS(ctx, phoneNumber, code, "1 hour")
}

// ResendPhoneVerification resends phone verification
func (s *NotificationService) ResendPhoneVerification(ctx context.Context, phoneNumber string) error {

	// Find existing verification token
	existingToken, err := s.verificationTokenRepo.FindByPhoneAndType(ctx, phoneNumber, string(models.TokenTypePhoneVerification))
	if err == nil && existingToken != nil {
		// Delete old token
		s.verificationTokenRepo.Delete(ctx, existingToken.ID, string(models.TokenTypePhoneVerification))
	}

	// Generate verification code (6-digit for phone)
	code, err := s.deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate numeric OTP: %w", err)
	}

	// Create verification token record
	verificationToken := &models.VerificationToken{
		ID:          uuid.New().String(),
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		PhoneNumber: phoneNumber,
		ExpiresAt:   time.Now().Add(15 * time.Minute), // 15 minutes expiry for phone
		Used:        false,
		CreatedAt:   time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: resent phone verification to %s", phoneNumber)
	user, err := s.userRepo.FindByPhoneNumber(ctx, phoneNumber)
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}
	return s.sendPhoneVerification(ctx, *user, code, "15 minutes")
}

// VerifyEmailWithToken verifies an email using token
func (s *NotificationService) VerifyEmail(ctx context.Context, token string) (*models.VerificationToken, error) {

	// Find the verification token
	verification, err := s.verificationTokenRepo.FindByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid verification token")
	}

	// Check if token is expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Check if token is already used
	if verification.Used {
		return nil, fmt.Errorf("verification token has already been used")
	}

	// Check if it's an email verification token
	if verification.Type != models.TokenTypeEmailVerification {
		return nil, fmt.Errorf("invalid token type")
	}
	user, err := s.userRepo.FindByEmail(ctx, verification.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	user.EmailVerified = true
	now := time.Now()
	user.UpdatedAt = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	if err := s.verificationTokenRepo.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("failed to mark token as used: %w", err)
	}

	s.deps.Logger.Infof("notification: verified email %s", verification.Email)

	return verification, nil
}

// VerifyPhoneWithCode verifies a phone using code
func (s *NotificationService) VerifyPhone(ctx context.Context, code string, phoneNumber string) (*models.VerificationToken, error) {

	// Find the verification token by code
	verification, err := s.verificationTokenRepo.FindByCode(ctx, code, string(models.TokenTypePhoneVerification))
	if err != nil {
		return nil, fmt.Errorf("invalid verification code")
	}

	// Check if code matches phone number
	if verification.PhoneNumber != phoneNumber {
		return nil, fmt.Errorf("code does not match phone number")
	}

	// Check if token is expired
	if verification.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("verification code has expired")
	}

	// Check if token is already used
	if verification.Used {
		return nil, fmt.Errorf("verification code has already been used")
	}

	// Mark token as used
	if err := s.verificationTokenRepo.MarkAsUsed(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}

	user, err := s.userRepo.FindByPhoneNumber(ctx, verification.PhoneNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	user.PhoneNumberVerified = true
	now := time.Now()
	user.UpdatedAt = &now
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	return verification, nil
}

// buildVerificationLink builds a verification link using frontend config
func (s *NotificationService) buildVerificationLink(email, token string) string {
	apiURL := s.deps.Config.APIURL + s.deps.Config.BasePath
	redirectUrl := fmt.Sprintf("%s%s", s.deps.Config.FrontendConfig.URL, s.deps.Config.FrontendConfig.VerifyEmailCallbackPath)
	verifificationLink := fmt.Sprintf("%s%s?token=%s&redirect_url=%s", apiURL, s.deps.Config.FrontendConfig.VerifyEmailCallbackPath, token, redirectUrl)
	return verifificationLink
}

func (s *NotificationService) buildPasswordResetLink(email, token string) string {
	// Try to use frontend config first
	if s.deps.Config.FrontendConfig != nil && s.deps.Config.FrontendConfig.ResetPasswordPath != "" {
		baseURL := s.deps.Config.FrontendConfig.URL
		if baseURL == "" {
			return ""
		}
		resetPath := s.deps.Config.FrontendConfig.ResetPasswordPath
		return fmt.Sprintf("%s%s?email=%s&code=%s", baseURL, resetPath, email, token)
	}
	return ""
}
