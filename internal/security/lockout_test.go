package security

import (
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/assert"
)

func defaultCfg() types.LockoutConfig {
	return types.LockoutConfig{
		Enabled:         true,
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
	}
}

func TestCheckLockout_NotLocked(t *testing.T) {
	user := &models.User{}
	assert.Nil(t, CheckLockout(user, defaultCfg()))
}

func TestCheckLockout_ActivelyLocked(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	user := &models.User{LockedUntil: &future, FailedLoginAttempts: 5}

	authErr := CheckLockout(user, defaultCfg())
	assert.NotNil(t, authErr)
	assert.Equal(t, types.ErrAccountLocked, authErr.Code)
}

func TestCheckLockout_LockExpired_ClearsState(t *testing.T) {
	past := time.Now().Add(-1 * time.Minute)
	user := &models.User{LockedUntil: &past, FailedLoginAttempts: 5}

	assert.Nil(t, CheckLockout(user, defaultCfg()))
	assert.Nil(t, user.LockedUntil, "lock should be cleared")
	assert.Equal(t, 0, user.FailedLoginAttempts, "attempts should be reset")
}

func TestCheckLockout_DisabledConfig(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	user := &models.User{LockedUntil: &future, FailedLoginAttempts: 5}

	cfg := types.LockoutConfig{Enabled: false}
	assert.Nil(t, CheckLockout(user, cfg))
}

func TestRecordFailedLogin_IncrementsCounter(t *testing.T) {
	user := &models.User{FailedLoginAttempts: 0}
	locked := RecordFailedLogin(user, defaultCfg())

	assert.False(t, locked)
	assert.Equal(t, 1, user.FailedLoginAttempts)
	assert.Nil(t, user.LockedUntil)
}

func TestRecordFailedLogin_LocksAtThreshold(t *testing.T) {
	user := &models.User{FailedLoginAttempts: 4} // one more = 5 = threshold
	locked := RecordFailedLogin(user, defaultCfg())

	assert.True(t, locked)
	assert.Equal(t, 5, user.FailedLoginAttempts)
	assert.NotNil(t, user.LockedUntil)
	assert.True(t, user.LockedUntil.After(time.Now()))
}

func TestRecordFailedLogin_DisabledConfig(t *testing.T) {
	user := &models.User{FailedLoginAttempts: 100}
	cfg := types.LockoutConfig{Enabled: false}
	locked := RecordFailedLogin(user, cfg)

	assert.False(t, locked)
	assert.Equal(t, 100, user.FailedLoginAttempts) // unchanged
}

func TestRecordSuccessfulLogin_ResetsState(t *testing.T) {
	future := time.Now().Add(10 * time.Minute)
	user := &models.User{FailedLoginAttempts: 3, LockedUntil: &future}

	RecordSuccessfulLogin(user)

	assert.Equal(t, 0, user.FailedLoginAttempts)
	assert.Nil(t, user.LockedUntil)
}

func TestNormalizeLockoutConfig_FillsDefaults(t *testing.T) {
	cfg := NormalizeLockoutConfig(types.LockoutConfig{Enabled: true})
	assert.Equal(t, 5, cfg.MaxAttempts)
	assert.Equal(t, 15*time.Minute, cfg.LockoutDuration)
}

func TestNormalizeLockoutConfig_PreservesExplicitValues(t *testing.T) {
	cfg := NormalizeLockoutConfig(types.LockoutConfig{
		Enabled:         true,
		MaxAttempts:     10,
		LockoutDuration: 30 * time.Minute,
	})
	assert.Equal(t, 10, cfg.MaxAttempts)
	assert.Equal(t, 30*time.Minute, cfg.LockoutDuration)
}
