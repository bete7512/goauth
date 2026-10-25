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
		return LockedError(cfg)
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

// HandleFailedLogin records a failed attempt, persists the user, emits an
// event when the account becomes locked, and returns the error to send:
// INVALID_CREDENTIALS, or LockedError when the attempt locked the account.
func HandleFailedLogin(
	ctx context.Context,
	user *models.User,
	cfg types.LockoutConfig,
	userRepo models.UserRepository,
	events types.EventBus,
	logger types.Logger,
) *types.GoAuthError {
	if !cfg.Enabled {
		return types.NewInvalidCredentialsError()
	}
	cfg = NormalizeLockoutConfig(cfg)
	var locked bool
	var err error
	if mutator, ok := userRepo.(models.UserAuthenticationMutator); ok {
		var updated *models.User
		updated, err = mutator.RecordFailedLogin(ctx, user.ID, user.TokenVersion, cfg.MaxAttempts, cfg.LockoutDuration)
		if err == nil {
			user = updated
			locked = user.LockedUntil != nil && time.Now().Before(*user.LockedUntil)
		}
	} else {
		locked = RecordFailedLogin(user, cfg)
		err = userRepo.Update(ctx, user)
	}
	if err != nil {
		logger.Error("failed to update failed login attempts", "error", err, "user_id", user.ID)
		return types.NewInvalidCredentialsError()
	}
	if locked && events != nil {
		_ = events.EmitAsync(ctx, types.EventSecurityAccountLocked, map[string]interface{}{
			"user_id":      user.ID,
			"locked_until": user.LockedUntil,
		})
	}
	if locked {
		return LockedError(cfg)
	}
	return types.NewInvalidCredentialsError()
}

// LockedError is the answer for a locked account. By default it is the same
// INVALID_CREDENTIALS response as a wrong password, so a caller cannot tell a
// lock from a wrong guess, confirm that the account exists, or learn that a
// deliberate lockout succeeded. RevealLocked opts into ACCOUNT_LOCKED (423).
func LockedError(cfg types.LockoutConfig) *types.GoAuthError {
	if cfg.RevealLocked {
		return types.NewAccountLockedError()
	}
	return types.NewInvalidCredentialsError()
}

// EqualizeUnknownUser spends one password hash when a login names an account
// that does not exist, so the answer takes as long as a wrong password for a
// real account and response timing does not reveal registered identifiers.
func EqualizeUnknownUser(manager types.SecurityManager, password string) {
	if manager == nil {
		return
	}
	_, _ = manager.HashPassword(password)
}
