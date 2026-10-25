package services

import (
	"context"
	"errors"
	"github.com/bete7512/goauth/internal/authentication"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Login authenticates user and creates session
func (s *sessionService) Login(ctx context.Context, req *dto.LoginRequest, metadata *types.RequestMetadata) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	user, err := s.userRepository.FindByEmail(ctx, req.Email)
	if err != nil {
		if !errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
		}
		// user not found by email, try username
		if req.Username != "" {
			user, err = s.userRepository.FindByUsername(ctx, req.Username)
			if err != nil {
				if !errors.Is(err, models.ErrNotFound) {
					return dto.AuthResponse{}, types.NewInternalError("failed to find user by username").Wrap(err)
				}
				security.EqualizeUnknownUser(s.securityManager, req.Password)
				return dto.AuthResponse{}, types.NewInvalidCredentialsError()
			}
		} else {
			security.EqualizeUnknownUser(s.securityManager, req.Password)
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
	}

	// Check the password before acting on the lockout state, so a locked
	// account answers in the same time as an unlocked one.
	lockoutCfg := security.NormalizeLockoutConfig(s.deps.Config.Security.Lockout)
	lockedErr := security.CheckLockout(user, lockoutCfg)
	passwordErr := s.securityManager.ValidatePassword(user.PasswordHash, req.Password)
	if lockedErr != nil {
		return dto.AuthResponse{}, lockedErr
	}
	if passwordErr != nil {
		return dto.AuthResponse{}, security.HandleFailedLogin(ctx, user, lockoutCfg, s.userRepository, s.deps.Events, s.deps.Logger)
	}

	// Clear any failed-attempt state on successful password check
	security.RecordSuccessfulLogin(user)

	completion := authentication.ForModule(s.deps, nil, s.sessionRepository, types.StrategySession)
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "password", Metadata: metadata})
	if authErr != nil {
		return dto.AuthResponse{}, authErr
	}
	if result.Status == types.ChallengeRequired {
		return dto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	accessToken, refreshToken, sessionID, responseData := result.AccessToken, result.RefreshToken, result.SessionID, result.Data

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	var updateErr error
	if mutator, ok := s.userRepository.(models.UserCredentialMutator); ok {
		updateErr = mutator.RecordLogin(ctx, user.ID, user.TokenVersion, now)
	} else {
		updateErr = s.userRepository.Update(ctx, user)
	}
	if err := updateErr; err != nil {
		s.logger.Errorf("failed to update user last login time: %v", err)
	}

	return dto.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
		User:         dto.UserToDTO(user),
		ExpiresIn:    result.ExpiresIn,
		Message:      "Login successful",
		Data:         responseData,
	}, nil
}
