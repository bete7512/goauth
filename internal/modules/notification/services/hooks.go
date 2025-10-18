package services

import (
	"context"
	"fmt"
	"time"

	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/google/uuid"
)

// SendEmailVerificationWithToken sends email verification and creates a token
func (s *NotificationService) SendEmailVerificationFromHook(ctx context.Context, user coreModels.User) error {

	// Generate verification token and code
	token, err := s.deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Build verification link
	verificationLink := s.buildVerificationLink(user.Email, token)
	// Create verification token record
	verificationToken := &models.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		Type:      models.TokenTypeEmailVerification,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours expiry
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: created verification token for email %s", user.Email)

	// Send email verification
	return s.sendEmailVerification(ctx, user.Email, "", verificationLink)
}

// SendPhoneVerificationWithToken sends phone verification and creates a token
func (s *NotificationService) SendPhoneVerificationFromHook(ctx context.Context, user coreModels.User) error {

	// Generate verification code (6-digit for phone)
	code, err := s.deps.SecurityManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate numeric OTP: %w", err)
	}

	// Create verification token record
	verificationToken := &models.VerificationToken{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Code:        code,
		Type:        models.TokenTypePhoneVerification,
		PhoneNumber: user.PhoneNumber,
		ExpiresAt:   time.Now().Add(15 * time.Minute), // 15 minutes expiry for phone
		Used:        false,
		CreatedAt:   time.Now(),
	}

	// Store verification token
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	s.deps.Logger.Infof("notification: created phone verification token for phone number %s", user.PhoneNumber)

	return s.sendPhoneVerification(ctx, user, code, "15 minutes")
}

func (s *NotificationService) SendWelcomeEmail(ctx context.Context, user coreModels.User) error {
	tmpl, ok := s.templates["welcome"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":  s.config.AppName,
		"UserName": user.Username,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}

func (s *NotificationService) SendLoginAlert(ctx context.Context, user coreModels.User, metadata map[string]interface{}) error {
	tmpl, ok := s.templates["login_alert"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":  user.Username,
		"IPAddress": metadata["ip_address"].(string),
		"Timestamp": metadata["timestamp"].(string),
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}

func (s *NotificationService) SendPasswordChangedAlert(ctx context.Context, user coreModels.User) error {
	tmpl, ok := s.templates["password_changed"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":    user.Username,
		"Timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"SupportLink": s.config.SupportLink,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}
