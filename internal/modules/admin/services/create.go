package services

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// CreateUserInput is a new account made by an administrator.
type CreateUserInput struct {
	Email         string
	Name          string
	Username      string // generated from the email when empty
	Password      string
	EmailVerified bool
	SuperAdmin    bool
}

// CreateUser creates an account with the same password policy and
// uniqueness rules as signup. The administrator chooses whether the email
// counts as verified.
func (s *adminService) CreateUser(ctx context.Context, input CreateUserInput) (*models.User, *types.GoAuthError) {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return nil, authErr
	}
	email := strings.TrimSpace(input.Email)
	if _, err := mail.ParseAddress(email); err != nil || !strings.Contains(email, "@") {
		return nil, types.NewValidationError("Enter a valid email address")
	}
	if s.deps.Config != nil {
		if err := s.deps.Config.Security.PasswordPolicy.Validate(input.Password); err != nil {
			return nil, types.NewValidationError(err.Error())
		}
	}
	if existing, err := s.userRepository.FindByEmail(ctx, email); err == nil && existing != nil {
		return nil, types.NewUserAlreadyExistsError()
	} else if err != nil && !errors.Is(err, models.ErrNotFound) {
		return nil, types.NewInternalError("failed to check email").Wrap(err)
	}
	username := strings.TrimSpace(input.Username)
	if username == "" {
		local := strings.Split(email, "@")[0]
		username = local + "-" + uuid.Must(uuid.NewV7()).String()[:8]
	} else if existing, err := s.userRepository.FindByUsername(ctx, username); err == nil && existing != nil {
		return nil, types.NewUsernameAlreadyExistsError()
	}
	hash, err := s.deps.SecurityManager.HashPassword(input.Password)
	if err != nil {
		return nil, types.NewInternalError("failed to hash password").Wrap(err)
	}
	now := time.Now()
	user := &models.User{
		ID:            uuid.Must(uuid.NewV7()).String(),
		Email:         email,
		Name:          strings.TrimSpace(input.Name),
		Username:      username,
		PasswordHash:  hash,
		Active:        true,
		EmailVerified: input.EmailVerified,
		IsSuperAdmin:  input.SuperAdmin,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}
	if err := s.userRepository.Create(ctx, user); err != nil {
		return nil, types.NewInternalError("failed to create user").Wrap(err)
	}
	_ = s.deps.Events.EmitAsync(ctx, types.EventAdminUserCreated, map[string]interface{}{
		"actor_id": actor.ID, "target_id": user.ID, "target_type": "user", "target_email": user.Email,
		"details": "Created user " + user.Email,
	})
	return user, nil
}

// Unlock clears a lockout caused by failed sign-in attempts.
func (s *adminService) Unlock(ctx context.Context, userID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	user, err := s.userRepository.FindByID(ctx, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && user == nil) {
		return types.NewUserNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load user").Wrap(err)
	}
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	if err := s.userRepository.Update(ctx, user); err != nil {
		return types.NewInternalError("failed to unlock user").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, "Unlocked the account")
	return nil
}

// SetPassword replaces a user's password, for a user who cannot use the
// reset email. Like a password change it signs the user out everywhere and
// clears any lockout. The new password must meet the password policy.
func (s *adminService) SetPassword(ctx context.Context, userID, password string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	if s.deps.Config != nil {
		if err := s.deps.Config.Security.PasswordPolicy.Validate(password); err != nil {
			return types.NewValidationError(err.Error())
		}
	}
	user, err := s.userRepository.FindByID(ctx, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && user == nil) {
		return types.NewUserNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load user").Wrap(err)
	}
	mutator, ok := s.userRepository.(models.UserCredentialMutator)
	if !ok {
		return types.NewInternalError("the user store cannot change passwords")
	}
	hash, err := s.deps.SecurityManager.HashPassword(password)
	if err != nil {
		return types.NewInternalError("failed to hash password").Wrap(err)
	}
	if err := mutator.ChangePassword(ctx, user.ID, user.PasswordHash, hash); err != nil {
		return types.NewInternalError("failed to set password").Wrap(err)
	}
	if sessions := s.deps.Storage.Session(); sessions != nil && s.deps.Config.Security.AuthStrategy == types.StrategySession {
		_ = sessions.Sessions().DeleteByUserID(ctx, user.ID)
	}
	s.securityEvent(ctx, actor.ID, user.ID, "Set a new password")
	return nil
}
