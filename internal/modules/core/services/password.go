package core_services

import (
	"context"
	"errors"
	"github.com/bete7512/goauth/internal/operation"
	"github.com/bete7512/goauth/pkg/config"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// ForgotPassword initiates password reset process.
func (s *coreService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) (*dto.MessageResponse, *types.GoAuthError) {
	var user *models.User
	var err error
	var token, code string

	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else if req.Phone != "" {
		user, err = s.UserRepository.FindByPhoneNumber(ctx, req.Phone)
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "email or phone is required", 400)
	}

	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return &dto.MessageResponse{
				Message: "If an account exists, password reset instructions have been sent",
			}, nil
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}

	// Rate limit: check if a recent reset token already exists for this email
	existing, _ := s.TokenRepository.FindByEmailAndType(ctx, user.Email, models.TokenTypePasswordReset)
	if existing != nil && !existing.Used && time.Since(existing.CreatedAt) < 2*time.Minute {
		// Silently return success without creating another token to avoid revealing account info
		return &dto.MessageResponse{
			Message: "If an account exists, password reset instructions have been sent",
		}, nil
	}

	// Every row gets an opaque token: the tokens.token column is unique, so
	// phone-only requests must not share an empty value. The link is only
	// delivered by email; phone users receive the short code.
	token, err = s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError("failed to generate token").Wrap(err)
	}

	if req.Phone != "" {
		code, err = s.Deps.SecurityManager.GenerateNumericOTP(6)
		if err != nil {
			return nil, types.NewInternalError("failed to generate OTP").Wrap(err)
		}
	}

	resetLink := s.buildPasswordResetLink(token)

	// Create password reset token
	verificationToken := &models.Token{
		ID:          uuid.Must(uuid.NewV7()).String(),
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
		return nil, types.NewInternalError("failed to create reset token").Wrap(err)
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
	if s.Deps.Config.DurableEvents && !s.inTransaction {
		return operation.Run(ctx, s.Deps, func(deps config.ModuleDependencies) (*dto.MessageResponse, *types.GoAuthError) {
			copy := *s
			copy.Deps = deps
			copy.inTransaction = true
			copy.UserRepository = deps.Storage.Core().Users()
			copy.TokenRepository = deps.Storage.Core().Tokens()
			return copy.ResetPassword(ctx, req)
		})
	}

	if err := s.Deps.Config.Security.PasswordPolicy.Validate(req.NewPassword); err != nil {
		return nil, types.NewValidationError(err.Error())
	}
	var verification *models.Token
	var err error

	// Find reset token
	if req.Token != "" {
		verification, err = s.TokenRepository.FindByToken(ctx, req.Token)
		if err != nil {
			if errors.Is(err, models.ErrNotFound) {
				return nil, types.NewInvalidTokenError()
			}
			return nil, types.NewInternalError("failed to find reset token").Wrap(err)
		}
	} else if req.Code != "" {
		if req.Phone == "" {
			return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "phone is required when using reset code", 400)
		}
		// Resolve the token by the account it was issued to, never by the
		// submitted code, so wrong guesses count against that token.
		verification, err = s.TokenRepository.FindByPhoneAndType(ctx, req.Phone, models.TokenTypePasswordReset)
		if err != nil {
			if errors.Is(err, models.ErrNotFound) {
				return nil, types.NewInvalidTokenError()
			}
			return nil, types.NewInternalError("failed to find reset code").Wrap(err)
		}
		if authErr := s.checkCode(ctx, verification, req.Code); authErr != nil {
			return nil, authErr
		}
	} else {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "reset token or code is required", 400)
	}

	if verification.Type != models.TokenTypePasswordReset {
		return nil, types.NewInvalidTokenError()
	}
	if req.Code != "" && (req.Phone == "" || verification.PhoneNumber != req.Phone) {
		return nil, types.NewInvalidTokenError()
	}
	if !time.Now().Before(verification.ExpiresAt) {
		return nil, types.NewTokenExpiredError()
	}

	if verification.Used {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "reset token has already been used", 400)
	}

	// Find user
	user, err := s.UserRepository.FindByID(ctx, verification.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}

	now := time.Now()
	hashedPassword, err := s.SecurityManager.HashPassword(req.NewPassword)
	if err != nil {
		return nil, types.NewInternalError("failed to hash password").Wrap(err)
	}

	previousHash := user.PasswordHash
	user.PasswordHash = string(hashedPassword)
	user.TokenVersion++
	user.UpdatedAt = &now

	store := s.coreStorage()
	if store == nil {
		return nil, types.NewInternalError("password recovery requires transactional core storage")
	}
	if err := store.WithTransaction(ctx, func(tx types.CoreStorage) error {
		if err := tx.Tokens().MarkAsUsed(ctx, verification.ID); err != nil {
			return err
		}
		if mutator, ok := tx.Users().(models.UserCredentialMutator); ok {
			return mutator.ChangePassword(ctx, user.ID, previousHash, user.PasswordHash)
		}
		return tx.Users().Update(ctx, user)
	}); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewInvalidTokenError()
		}
		return nil, types.NewInternalError("failed to reset password").Wrap(err)
	}

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
	if s.Deps.Config.DurableEvents && !s.inTransaction {
		return operation.Run(ctx, s.Deps, func(deps config.ModuleDependencies) (*dto.MessageResponse, *types.GoAuthError) {
			copy := *s
			copy.Deps = deps
			copy.inTransaction = true
			copy.UserRepository = deps.Storage.Core().Users()
			copy.TokenRepository = deps.Storage.Core().Tokens()
			return copy.ChangePassword(ctx, userID, req)
		})
	}

	if err := s.Deps.Config.Security.PasswordPolicy.Validate(req.NewPassword); err != nil {
		return nil, types.NewValidationError(err.Error())
	}
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}

	now := time.Now()
	if err := s.SecurityManager.ValidatePassword(user.PasswordHash, req.OldPassword); err != nil {
		return nil, types.NewInvalidCredentialsError()
	}

	hashedPassword, err := s.SecurityManager.HashPassword(req.NewPassword)
	if err != nil {
		return nil, types.NewInternalError("failed to hash password").Wrap(err)
	}

	previousHash := user.PasswordHash
	user.PasswordHash = string(hashedPassword)
	user.TokenVersion++
	user.UpdatedAt = &now

	var updateErr error
	if mutator, ok := s.UserRepository.(models.UserCredentialMutator); ok {
		updateErr = mutator.ChangePassword(ctx, user.ID, previousHash, user.PasswordHash)
	} else {
		updateErr = s.UserRepository.Update(ctx, user)
	}
	if err := updateErr; err != nil {
		return nil, types.NewInternalError("failed to update password").Wrap(err)
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
