package twofactor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newTestRepo(t *testing.T) *twoFactorRepository {
	t.Helper()
	dsn := fmt.Sprintf("file:tf_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.TwoFactor{}))
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &twoFactorRepository{db: db}
}

func TestConsumeTOTPStepHasExactlyOneWinner(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	require.NoError(t, repo.Create(ctx, &models.TwoFactor{UserID: "u1", Secret: "s", Enabled: true, LastUsedStep: 10}))

	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := repo.ConsumeTOTPStep(ctx, "u1", 11); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, models.ErrConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), wins.Load(), "exactly one concurrent submission wins")
	require.Equal(t, int32(31), conflicts.Load())

	require.ErrorIs(t, repo.ConsumeTOTPStep(ctx, "u1", 11), models.ErrConflict, "same step again")
	require.ErrorIs(t, repo.ConsumeTOTPStep(ctx, "u1", 9), models.ErrConflict, "older step")
	require.NoError(t, repo.ConsumeTOTPStep(ctx, "u1", 12))
	require.ErrorIs(t, repo.ConsumeTOTPStep(ctx, "nobody", 1), models.ErrConflict, "unknown user")

	tf, err := repo.GetByUserID(ctx, "u1")
	require.NoError(t, err)
	require.EqualValues(t, 12, tf.LastUsedStep)
}

func TestConsumeTOTPStepClearsFailureState(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	locked := time.Now().Add(10 * time.Minute)
	require.NoError(t, repo.Create(ctx, &models.TwoFactor{UserID: "u1", Secret: "s", Enabled: true, FailedAttempts: 4, LockedUntil: &locked}))

	require.NoError(t, repo.ConsumeTOTPStep(ctx, "u1", 1))
	tf, err := repo.GetByUserID(ctx, "u1")
	require.NoError(t, err)
	require.Equal(t, 0, tf.FailedAttempts)
	require.Nil(t, tf.LockedUntil)
}
