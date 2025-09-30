package user_service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

func (s *UserService) CreateUser(ctx context.Context, user *models.User) *types.GoAuthError {
	err := s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return types.NewInternalError(err.Error())
	}
	// validation have to be done in the handler
	// check password if exists
	// hash password 
	// save user
	// send welcome email
	// send verification email
	// send verification sms
	// send verification phone
	// send verification action confirmation
	// send verification magic link
	existingUser, err := s.userRepo.GetUserByEmail(ctx, user.Email)
	if err != nil {
		return types.NewInternalError(err.Error())
	}
	if existingUser != nil {
		return types.NewUserAlreadyExistsError()
	}

	hashedPassword, err := s.tokenMgr.HashPassword(user.Password)
	if err != nil {
		return types.NewInternalError(err.Error())
	}
	
	user.Password = hashedPassword
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}


func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*dto.UserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}
	return &dto.UserResponse{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    *user.EmailVerified,
		PhoneVerified:    *user.PhoneVerified,
		TwoFactorEnabled: *user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}, nil
}

func (s *UserService) GetUserByPhoneNumber(ctx context.Context, phone string) (*dto.UserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByPhoneNumber(ctx, phone)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}
	return &dto.UserResponse{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    *user.EmailVerified,
		PhoneVerified:    *user.PhoneVerified,
		TwoFactorEnabled: *user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}, nil
}
// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	return &dto.UserResponse{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    *user.EmailVerified,
		PhoneVerified:    *user.PhoneVerified,
		TwoFactorEnabled: *user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}, nil
}

// UpdateProfile updates user profile
func (s *UserService) UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
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

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.UserResponse{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    *user.EmailVerified,
		PhoneVerified:    *user.PhoneVerified,
		TwoFactorEnabled: *user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}, nil
}

// DeactivateUser deactivates a user account
func (s *UserService) DeactivateUser(ctx context.Context, userID string, req *dto.DeactivateUserRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return types.NewUserNotFoundError()
	}

	active := false
	user.Active = &active
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return types.NewInternalError(err.Error())
	}

	return nil
}

func (s *UserService) GetMe(ctx context.Context, userID string) (*dto.UserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	return &dto.UserResponse{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		EmailVerified:    *user.EmailVerified,
		PhoneVerified:    *user.PhoneVerified,
		TwoFactorEnabled: *user.TwoFactorEnabled,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}, nil
}

// SendEmailVerification sends email verification
func (s *UserService) SendEmailVerification(ctx context.Context, email string) *types.GoAuthError {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return types.NewUserNotFoundError()
		}
		return types.NewInternalError(err.Error())
	}
	if user.EmailVerified != nil && *user.EmailVerified {
		return types.NewEmailAlreadyVerifiedError()
	}

	// s.sendEmailVerification(ctx, user)
	s.config.WorkerPool.Submit(func() {
		if s.config.Email.CustomSender != nil {
			if err := s.config.Email.CustomSender.SendVerificationEmail(ctx, *user, s.config.App.FrontendURL); err != nil {
				s.logger.Errorf("Failed to send email verification: %v", err)
			}
		}
	})

	return nil
}

// VerifyEmail verifies email address
func (s *UserService) VerifyEmail(ctx context.Context, req *dto.EmailVerificationRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Errorf("failed to get user by email: %v", err)
		return types.NewInternalError(err.Error())
	}

	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.EmailVerificationToken)
	if err != nil {
		s.logger.Errorf("failed to get active token by user id and type: %v", err)
		return types.NewInternalError(err.Error())
	}

	if token == nil {
		s.logger.Errorf("token not found")
		return types.NewTokenNotFoundError()
	}

	ierr := s.tokenMgr.ValidateHashedToken(token.TokenValue, req.Token)
	if ierr != nil {
		s.logger.Errorf("failed to validate hashed token: %v", ierr)
		return types.NewInvalidTokenError()
	}

	err = s.tokenRepo.RevokeToken(ctx, token.ID)
	if err != nil {
		return types.NewInternalError(err.Error())
	}

	active := true
	verified := true
	emailVerifiedAt := time.Now()
	user.EmailVerified = &verified
	user.EmailVerifiedAt = &emailVerifiedAt
	user.Active = &active
	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Errorf("failed to update user: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}

// SendPhoneVerification sends phone verification
func (s *UserService) SendPhoneVerification(ctx context.Context, phoneNumber string) *types.GoAuthError {
	user, err := s.userRepo.GetUserByPhoneNumber(ctx, phoneNumber)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}
	if user.PhoneVerified != nil && *user.PhoneVerified {
		s.logger.Errorf("phone already verified")
		return types.NewPhoneAlreadyVerifiedError()
	}

	s.config.WorkerPool.Submit(func() {
		if s.config.SMS.CustomSender != nil {
			if err := s.config.SMS.CustomSender.SendVerificationSMS(ctx, *user, s.config.App.FrontendURL); err != nil {
				s.logger.Errorf("Failed to send phone verification: %v", err)
			}
		}
	})

	return nil
}

// VerifyPhone verifies phone number
func (s *UserService) VerifyPhone(ctx context.Context, req *dto.PhoneVerificationRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByPhoneNumber(ctx, req.PhoneNumber)
	if err != nil {
		s.logger.Errorf("failed to get user: %v", err)
		return types.NewInternalError(err.Error())
	}
	if user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}
	if user.PhoneVerified != nil && *user.PhoneVerified {
		s.logger.Errorf("phone already verified")
		return types.NewPhoneAlreadyVerifiedError()
	}
	

	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.PhoneVerificationToken)
	if err != nil {
		s.logger.Errorf("failed to get token: %v", err)
		return types.NewInternalError(err.Error())
	}

	if token == nil {
		s.logger.Errorf("token not found")
		return types.NewTokenNotFoundError()
	}

	ierr := s.tokenMgr.ValidateHashedToken(token.TokenValue, req.Code)
	if ierr != nil {
		s.logger.Errorf("failed to verify token: %v", ierr)
		return types.NewInvalidTokenError()
	}

	err = s.tokenRepo.RevokeToken(ctx, token.ID)
	if err != nil {
		s.logger.Errorf("failed to revoke token: %v", err)
		return types.NewInternalError(err.Error())
	}

	active := true
	verified := true
	user.PhoneVerified = &verified
	phoneVerifiedAt := time.Now()
	user.PhoneVerifiedAt = &phoneVerifiedAt
	user.Active = &active

	err = s.userRepo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Errorf("failed to update user: %v", err)
		return types.NewInternalError(err.Error())
	}

	s.logger.Infof("Phone verified for user %s", user.ID)

	return nil
}

// SendActionConfirmation sends action confirmation
func (s *UserService) SendActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Generate confirmation token
	confirmationToken, ierr := s.tokenMgr.GenerateRandomToken(32)
	if ierr != nil {
		s.logger.Errorf("failed to generate confirmation token: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}

	hashedToken, ierr := s.tokenMgr.HashToken(confirmationToken)
	if ierr != nil {
		s.logger.Errorf("failed to hash confirmation token: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}

	// Save confirmation token (1 hour expiry)
	expiry := time.Hour
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedToken, models.ActionConfirmationToken, expiry); err != nil {
		s.logger.Errorf("failed to save confirmation token: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Create confirmation URL
	confirmationURL := fmt.Sprintf("%s/action/verify?token=%s&action=%s", s.config.App.FrontendURL, confirmationToken, req.ActionType)

	// Send confirmation email
	if s.config.Email.CustomSender != nil {
		if err := s.config.Email.CustomSender.SendVerificationEmail(ctx, *user, confirmationURL); err != nil {
			s.logger.Errorf("failed to send confirmation email: %v", err)
			return types.NewInternalError(err.Error())
		}
	}

	return nil
}

// VerifyActionConfirmation verifies action confirmation
func (s *UserService) VerifyActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationVerificationRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Errorf("failed to get user: %v", err)
		return types.NewInternalError(err.Error())
	}

	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.ActionConfirmationToken)
	if err != nil {
		s.logger.Errorf("failed to get token: %v", err)
		return types.NewInternalError(err.Error())
	}

	if token == nil {
		s.logger.Errorf("token not found")
		return types.NewTokenNotFoundError()
	}

	ierr := s.tokenMgr.ValidateHashedToken(token.TokenValue, req.Code)
	if err != nil {
		s.logger.Errorf("failed to verify token: %v", ierr)
		return types.NewInvalidTokenError()
	}

	err = s.tokenRepo.RevokeToken(ctx, token.ID)
	if err != nil {
			s.logger.Errorf("failed to revoke token: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}
