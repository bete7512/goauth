package security

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// DefaultLockoutConfig returns a LockoutConfig with sensible defaults.
func DefaultLockoutConfig() types.LockoutConfig {
	return types.LockoutConfig{
		Enabled:         true,
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
	}
}

// NormalizeLockoutConfig fills zero-value fields with defaults.
func NormalizeLockoutConfig(cfg types.LockoutConfig) types.LockoutConfig {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.LockoutDuration <= 0 {
		cfg.LockoutDuration = 15 * time.Minute
	}
	return cfg
}

// CheckLockout returns an error if the user's account is currently locked.
// If the lock has expired it clears the lockout state on the user (caller must persist).
func CheckLockout(user *models.User, cfg types.LockoutConfig) *types.GoAuthError {
	if !cfg.Enabled {
		return nil
	}
	if user.LockedUntil == nil {
		return nil
	}
	if time.Now().Before(*user.LockedUntil) {
		return types.NewAccountLockedError()
	}
	// Lock expired — clear it so the user can try again
	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	return nil
}

// RecordFailedLogin increments the failed-attempt counter and locks the account
// if the threshold is reached. The caller must persist the user after calling this.
// Returns true if the account was just locked.
func RecordFailedLogin(user *models.User, cfg types.LockoutConfig) bool {
	if !cfg.Enabled {
		return false
	}
	user.FailedLoginAttempts++
	if user.FailedLoginAttempts >= cfg.MaxAttempts {
		lockUntil := time.Now().Add(cfg.LockoutDuration)
		user.LockedUntil = &lockUntil
		return true
	}
	return false
}

// RecordSuccessfulLogin resets the failed-attempt counter and clears any lock.
// The caller must persist the user after calling this.
func RecordSuccessfulLogin(user *models.User) {
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
}

// HandleFailedLogin is a convenience that records a failed attempt, persists
// the user, optionally emits an event if the account was locked, and returns
// the appropriate error (always ErrInvalidCredentials — we never leak lockout
// status before it's actually locked).
func HandleFailedLogin(
	ctx context.Context,
	user *models.User,
	cfg types.LockoutConfig,
	userRepo models.UserRepository,
	events types.EventBus,
	logger types.Logger,
) *types.GoAuthError {
	locked := RecordFailedLogin(user, cfg)
	if err := userRepo.Update(ctx, user); err != nil {
		logger.Error("failed to update failed login attempts", "error", err, "user_id", user.ID)
	}
	if locked && events != nil {
		_ = events.EmitAsync(ctx, types.EventSecurityAccountLocked, map[string]interface{}{
			"user_id":      user.ID,
			"locked_until": user.LockedUntil,
		})
	}
	if locked {
		return types.NewAccountLockedError()
	}
	return types.NewInvalidCredentialsError()
}
