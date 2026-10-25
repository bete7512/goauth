package services

import (
	"context"
	"errors"
	"github.com/bete7512/goauth/internal/authentication"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Login authenticates user and generates JWT tokens with nonce-based refresh token
func (s *StatelessService) Login(ctx context.Context, req *dto.LoginRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	user, err := s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil {
		if !errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
		}
		// user not found by email, try username
		if req.Username != "" {
			user, err = s.UserRepository.FindByUsername(ctx, req.Username)
			if err != nil {
				if !errors.Is(err, models.ErrNotFound) {
					return dto.AuthResponse{}, types.NewInternalError("failed to find user by username").Wrap(err)
				}
				security.EqualizeUnknownUser(s.SecurityManager, req.Password)
				return dto.AuthResponse{}, types.NewInvalidCredentialsError()
			}
		} else {
			security.EqualizeUnknownUser(s.SecurityManager, req.Password)
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
	}

	// Check the password before acting on the lockout state, so a locked
	// account answers in the same time as an unlocked one.
	lockoutCfg := security.NormalizeLockoutConfig(s.Deps.Config.Security.Lockout)
	lockedErr := security.CheckLockout(user, lockoutCfg)
	passwordErr := s.SecurityManager.ValidatePassword(user.PasswordHash, req.Password)
	if lockedErr != nil {
		return dto.AuthResponse{}, lockedErr
	}
	if passwordErr != nil {
		return dto.AuthResponse{}, security.HandleFailedLogin(ctx, user, lockoutCfg, s.UserRepository, s.Deps.Events, s.Deps.Logger)
	}

	// Clear any failed-attempt state on successful password check
	security.RecordSuccessfulLogin(user)

	completion := authentication.ForModule(s.Deps, s.TokenRepository, nil, types.StrategyStateless)
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "password"})
	if authErr != nil {
		return dto.AuthResponse{}, authErr
	}
	if result.Status == types.ChallengeRequired {
		return dto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	accessToken, refreshToken, responseData := result.AccessToken, result.RefreshToken, result.Data

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	var updateErr error
	if mutator, ok := s.UserRepository.(models.UserCredentialMutator); ok {
		updateErr = mutator.RecordLogin(ctx, user.ID, user.TokenVersion, now)
	} else {
		updateErr = s.UserRepository.Update(ctx, user)
	}
	if err := updateErr; err != nil {
		s.Logger.Errorf("failed to update user last login time: %v", err)
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User:         dto.UserToDTO(user),
		ExpiresIn:    result.ExpiresIn,
		Message:      "Login successful",
		Data:         responseData,
	}, nil
}
