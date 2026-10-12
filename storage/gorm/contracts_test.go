package gorm_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// CI supplies a disposable PostgreSQL/MySQL database. Local runs use SQLite.
func contractStore(t *testing.T) *store.GormStorage {
	t.Helper()
	dialect, dsn := types.DialectType(os.Getenv("GOAUTH_CONTRACT_DIALECT")), os.Getenv("GOAUTH_CONTRACT_DSN")
	connections := 16
	if dialect == "" {
		dialect = types.DialectTypeSqlite
		dsn = "file:" + uuid.NewString() + "?mode=memory&cache=shared&_busy_timeout=5000"
		connections = 1
	}
	s, err := store.NewStorage(store.Config{Dialect: dialect, DSN: dsn, LogLevel: "silent", MaxOpenConns: connections, MaxIdleConns: connections})
	require.NoError(t, err)
	a, err := auth.New(&config.Config{Storage: s, BorrowStorage: true, Security: types.SecurityConfig{JwtSecretKey: "contract-test-secret-32-characters", EncryptionKey: "contract-test-encryption-secret"}, Migration: config.MigrationConfig{Auto: true}})
	require.NoError(t, err)
	require.NoError(t, a.Use(session.New(nil)))
	require.NoError(t, a.Use(twofactor.New(nil)))
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()); require.NoError(t, s.Close()) })
	return s
}

func tokenRecord(user string) *models.Token {
	return &models.Token{ID: uuid.NewString(), UserID: user, Type: "refresh_nonce", Token: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
}

func TestAccountMutationContracts(t *testing.T) {
	s := contractStore(t)
	ctx := context.Background()
	id := uuid.NewString()
	repo := s.Core().Users()
	require.NoError(t, repo.Create(ctx, &models.User{ID: id, Email: id + "@example.com", Username: id, PasswordHash: "old-hash", Active: true}))
	attempts := repo.(models.UserAuthenticationMutator)
	credentials := repo.(models.UserCredentialMutator)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := attempts.RecordFailedLogin(ctx, id, 0, 16, time.Minute)
			if err != nil {
				t.Errorf("atomic attempt: %v", err)
			}
		}()
	}
	group.Wait()
	user, err := repo.FindByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, 16, user.FailedLoginAttempts)
	require.NotNil(t, user.LockedUntil)
	_, err = attempts.RecordFailedLogin(ctx, id, 0, 16, time.Minute)
	require.ErrorIs(t, err, models.ErrConflict)
	require.NoError(t, credentials.ChangePassword(ctx, id, "old-hash", "new-hash"))
	_, err = attempts.RecordFailedLogin(ctx, id, 0, 16, time.Minute)
	require.ErrorIs(t, err, models.ErrConflict, "stale authentication must not overwrite reset state")
	require.ErrorIs(t, credentials.RecordLogin(ctx, id, 0, time.Now()), models.ErrConflict)
	require.NoError(t, attempts.VerifyContact(ctx, id, user.Email, true))
	require.ErrorIs(t, attempts.VerifyContact(ctx, id, "changed@example.com", true), models.ErrConflict)
	user, err = repo.FindByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "new-hash", user.PasswordHash)
	require.Equal(t, 1, user.TokenVersion)
	require.Equal(t, 0, user.FailedLoginAttempts)
	require.True(t, user.EmailVerified)
}

func runContenders(t *testing.T, fn func(int) error) {
	t.Helper()
	var wins atomic.Int32
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			err := fn(i)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, models.ErrConflict) {
				t.Errorf("unexpected contention error: %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	require.Equal(t, int32(1), wins.Load(), "exactly one transition must commit")
}

func TestCredentialStorageContracts(t *testing.T) {
	s := contractStore(t)
	ctx := context.Background()
	repo := s.Core().Tokens()
	userID := uuid.NewString()
	require.NoError(t, s.Core().Users().Create(ctx, &models.User{ID: userID, Email: userID + "@example.com", Username: userID, Active: true}))
	t.Run("single consumption", func(t *testing.T) {
		token := tokenRecord(userID)
		require.NoError(t, repo.Create(ctx, token))
		runContenders(t, func(_ int) error { return repo.MarkAsUsed(ctx, token.ID) })
	})
	t.Run("backup code single consumption", func(t *testing.T) {
		code := &models.BackupCode{ID: uuid.NewString(), UserID: userID, Code: "contract-hash", CreatedAt: time.Now()}
		repo := s.TwoFactorAuth().BackupCodes()
		require.NoError(t, repo.CreateBatch(ctx, []*models.BackupCode{code}))
		runContenders(t, func(_ int) error { return repo.MarkUsed(ctx, code.ID) })
	})
	t.Run("expired consumption", func(t *testing.T) {
		token := tokenRecord(userID)
		token.ExpiresAt = time.Now().Add(-time.Minute)
		require.NoError(t, repo.Create(ctx, token))
		require.ErrorIs(t, repo.MarkAsUsed(ctx, token.ID), models.ErrConflict)
	})
	t.Run("atomic rotation", func(t *testing.T) {
		token := tokenRecord(userID)
		require.NoError(t, repo.Create(ctx, token))
		runContenders(t, func(_ int) error { return repo.(models.TokenRotator).Rotate(ctx, token, tokenRecord(userID)) })
	})
	t.Run("rotation rollback", func(t *testing.T) {
		token := tokenRecord(userID)
		require.NoError(t, repo.Create(ctx, token))
		replacement := tokenRecord(userID)
		replacement.ID = token.ID
		require.Error(t, repo.(models.TokenRotator).Rotate(ctx, token, replacement))
		stored, err := repo.FindByToken(ctx, token.Token)
		require.NoError(t, err)
		require.False(t, stored.Used)
		require.NoError(t, repo.(models.TokenRotator).Rotate(ctx, token, tokenRecord(userID)))
	})
	t.Run("stable session rotation", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		original := models.Session{ID: uuid.NewString(), UserID: userID, RefreshToken: uuid.NewString(), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour), RefreshTokenExpiresAt: now.Add(time.Hour)}
		repo := s.Session().Sessions()
		require.NoError(t, repo.Create(ctx, &original))
		runContenders(t, func(_ int) error {
			replacement := original
			replacement.RefreshToken = uuid.NewString()
			return repo.(models.SessionRotator).RotateToken(ctx, original.RefreshToken, &replacement)
		})
		stored, err := repo.FindByID(ctx, original.ID)
		require.NoError(t, err)
		require.True(t, original.CreatedAt.Equal(stored.CreatedAt))
		require.True(t, original.ExpiresAt.Equal(stored.ExpiresAt))
	})
	t.Run("cross feature rollback", func(t *testing.T) {
		token := tokenRecord(userID)
		err := s.WithTransaction(ctx, func(tx types.Storage) error {
			if err := tx.Core().Tokens().Create(ctx, token); err != nil {
				return err
			}
			return errors.New("injected failure")
		})
		require.Error(t, err)
		_, err = repo.FindByToken(ctx, token.Token)
		require.ErrorIs(t, err, models.ErrNotFound)
	})
}

func TestMigrationRecordContracts(t *testing.T) {
	s := contractStore(t)
	ctx := context.Background()
	records, err := s.AppliedMigrations(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, records)
	for _, record := range records {
		require.Len(t, record.Checksum, 64)
		require.False(t, record.Dirty)
	}
	err = s.WithMigrationLock(ctx, func(applier types.MigrationApplier) error {
		record := types.MigrationRecord{ID: uuid.NewString(), ModuleName: "failure_probe_" + uuid.NewString(), Version: 0, Name: "failure", Dialect: string(s.Dialect()), AppliedAt: time.Now(), Checksum: "fixture"}
		err := applier.(types.AtomicMigrationApplier).ApplyMigration(ctx, record, []byte("CREATE TABLE goauth_rollback_probe (id INTEGER); THIS IS INVALID SQL;"))
		require.Error(t, err)
		records, listErr := applier.AppliedMigrations(ctx)
		require.NoError(t, listErr)
		found := false
		for _, r := range records {
			if r.ID == record.ID {
				found = true
				require.True(t, r.Dirty)
			}
		}
		if s.Dialect() == types.DialectTypeMysql {
			require.True(t, found)
			require.NoError(t, applier.ExecMigration(ctx, []byte("DROP TABLE goauth_rollback_probe;")))
			require.NoError(t, applier.RemoveMigrationRecord(ctx, record.ModuleName, 0))
		} else {
			require.False(t, found)
		}
		return nil
	})
	require.NoError(t, err)
}
