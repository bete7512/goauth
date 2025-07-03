package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.UserResponse{
		Message: "user retrieved successfully",
		User:    s.mapUserToDTO(user),
	}, nil
}

// UpdateProfile updates user profile
func (s *AuthService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Update fields if provided
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = &req.PhoneNumber
	}

	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &dto.UserResponse{
		Message: "profile updated successfully",
		User:    s.mapUserToDTO(user),
	}, nil
}

// DeactivateUser deactivates a user account
func (s *AuthService) DeactivateUser(ctx context.Context, userID string, req *dto.DeactivateUserRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	active := false
	user.Active = &active
	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	return nil
}

// SendEmailVerification sends email verification
func (s *AuthService) SendEmailVerification(ctx context.Context, userID string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Generate verification token
	verificationToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(verificationToken)
	if err != nil {
		return fmt.Errorf("failed to hash verification token: %w", err)
	}

	// Save verification token (24 hours expiry)
	expiry := 24 * time.Hour
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.EmailVerificationToken, expiry); err != nil {
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	// Create verification URL
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.Auth.Config.App.FrontendURL, verificationToken)

	// Send verification email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendVerificationEmail(ctx, *user, verificationURL); err != nil {
			return fmt.Errorf("failed to send verification email: %w", err)
		}
	}

	return nil
}

// VerifyEmail verifies email address
func (s *AuthService) VerifyEmail(ctx context.Context, req *dto.EmailVerificationRequest) error {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Update user email verification status
	// This would require finding the user by token and updating their email verification status

	return errors.New("not implemented")
}

// SendPhoneVerification sends phone verification
func (s *AuthService) SendPhoneVerification(ctx context.Context, userID string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	if user.PhoneNumber == nil || *user.PhoneNumber == "" {
		return errors.New("phone number not set")
	}

	// Generate OTP
	otp, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	hashedOTP, err := s.Auth.TokenManager.HashToken(*user.PhoneNumber)
	if err != nil {
		return fmt.Errorf("failed to hash OTP: %w", err)
	}

	// Save OTP (10 minutes expiry)
	expiry := 10 * time.Minute
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedOTP, models.PhoneVerificationToken, expiry); err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	// Send SMS
	if s.Auth.Config.SMS.CustomSender != nil {
		if err := s.Auth.Config.SMS.CustomSender.SendVerificationSMS(ctx, *user, otp); err != nil {
			return fmt.Errorf("failed to send SMS: %w", err)
		}
	}

	return nil
}

// VerifyPhone verifies phone number
func (s *AuthService) VerifyPhone(ctx context.Context, req *dto.PhoneVerificationRequest) error {
	// TODO: Implement OTP verification logic
	// For now, we'll assume the OTP is valid

	// TODO: Update user phone verification status
	// This would require finding the user by OTP and updating their phone verification status

	return errors.New("not implemented")
}

// SendActionConfirmation sends action confirmation
func (s *AuthService) SendActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Generate confirmation token
	confirmationToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate confirmation token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(confirmationToken)
	if err != nil {
		return fmt.Errorf("failed to hash confirmation token: %w", err)
	}

	// Save confirmation token (1 hour expiry)
	expiry := time.Hour
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedToken, models.ActionConfirmationToken, expiry); err != nil {
		return fmt.Errorf("failed to save confirmation token: %w", err)
	}

	// Create confirmation URL
	confirmationURL := fmt.Sprintf("%s/action/verify?token=%s&action=%s", s.Auth.Config.App.FrontendURL, confirmationToken, req.ActionType)

	// Send confirmation email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendVerificationEmail(ctx, *user, confirmationURL); err != nil {
			return fmt.Errorf("failed to send confirmation email: %w", err)
		}
	}

	return nil
}

// VerifyActionConfirmation verifies action confirmation
func (s *AuthService) VerifyActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationVerificationRequest) error {
	// TODO: Implement token verification logic
	// For now, we'll assume the token is valid

	// TODO: Execute the confirmed action
	// This would require finding the user by token and executing the requested action

	return errors.New("not implemented")
}

func (s *AuthService) GetMe(ctx context.Context /*params*/) error {
	// TODO: Implement
	return nil
}
