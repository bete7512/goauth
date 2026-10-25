package services_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	services "github.com/bete7512/goauth/internal/modules/twofactor/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type quietLogger struct{}

func (quietLogger) Info(string, ...interface{})                      {}
func (quietLogger) Error(string, ...interface{})                     {}
func (quietLogger) Debug(string, ...interface{})                     {}
func (quietLogger) Warn(string, ...interface{})                      {}
func (quietLogger) Trace(string, ...interface{})                     {}
func (quietLogger) Infof(string, ...interface{})                     {}
func (quietLogger) Tracef(string, ...interface{})                    {}
func (quietLogger) Errorf(string, ...interface{})                    {}
func (quietLogger) Debugf(string, ...interface{})                    {}
func (quietLogger) Warnf(string, ...interface{})                     {}
func (quietLogger) Fatalf(string, ...interface{})                    {}
func (l quietLogger) WithFields(map[string]interface{}) types.Logger { return l }

const totpPeriod = 30

func newService(t *testing.T, ctrl *gomock.Controller, repo models.TwoFactorRepository) services.TwoFactorService {
	t.Helper()
	store := mocks.NewMockTwoFactorStorage(ctrl)
	store.EXPECT().TwoFactor().Return(repo).AnyTimes()
	deps := config.ModuleDependencies{
		Storage:         &types.StorageSet{TwoFactorStore: store},
		Config:          testutil.TestConfig(),
		Logger:          quietLogger{},
		SecurityManager: testutil.TestSecurityManager(),
	}
	return services.NewTwoFactorService(deps, "GoAuth", 8, 8)
}

func newSecret(t *testing.T) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "GoAuth", AccountName: "u1@example.com"})
	require.NoError(t, err)
	return key.Secret()
}

func enabledConfig(secret string) *models.TwoFactor {
	return &models.TwoFactor{ID: "tf-1", UserID: "u1", Secret: secret, Enabled: true, Verified: true, Method: "totp"}
}

// returnCopy hands the service a fresh copy each time, like a database read.
func returnCopy(cfg *models.TwoFactor) func(context.Context, string) (*models.TwoFactor, error) {
	return func(context.Context, string) (*models.TwoFactor, error) {
		c := *cfg
		return &c, nil
	}
}

func TestVerifyCodeConsumesStepAtomically(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockReplayGuardedTwoFactorRepository(ctrl)
	secret := newSecret(t)
	cfg := enabledConfig(secret)
	repo.EXPECT().GetByUserID(gomock.Any(), "u1").DoAndReturn(returnCopy(cfg)).AnyTimes()
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	step := now.Unix() / totpPeriod
	svc := newService(t, ctrl, repo)

	repo.EXPECT().ConsumeTOTPStep(gomock.Any(), "u1", step).Return(nil)
	require.Nil(t, svc.VerifyCode(context.Background(), "u1", code))

	// The store reports the step as already consumed: the replay is a failed attempt.
	repo.EXPECT().ConsumeTOTPStep(gomock.Any(), "u1", step).Return(models.ErrConflict)
	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		require.Equal(t, 1, tf.FailedAttempts)
		return nil
	})
	authErr := svc.VerifyCode(context.Background(), "u1", code)
	require.NotNil(t, authErr)
	require.Equal(t, types.NewTwoFactorInvalidError().Code, authErr.Code)
}

func TestVerifyCodeFallbackRejectsSequentialReplay(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockTwoFactorRepository(ctrl) // no atomic capability
	secret := newSecret(t)
	cfg := enabledConfig(secret)
	repo.EXPECT().GetByUserID(gomock.Any(), "u1").DoAndReturn(returnCopy(cfg)).AnyTimes()
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	step := now.Unix() / totpPeriod
	svc := newService(t, ctrl, repo)

	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		require.Equal(t, step, tf.LastUsedStep)
		require.Equal(t, 0, tf.FailedAttempts)
		cfg.LastUsedStep = tf.LastUsedStep
		return nil
	})
	require.Nil(t, svc.VerifyCode(context.Background(), "u1", code))

	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		require.Equal(t, 1, tf.FailedAttempts)
		return nil
	})
	require.NotNil(t, svc.VerifyCode(context.Background(), "u1", code), "same code twice")
}

func TestVerifyCodeWrongCodeCountsAttempt(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockReplayGuardedTwoFactorRepository(ctrl)
	secret := newSecret(t)
	repo.EXPECT().GetByUserID(gomock.Any(), "u1").DoAndReturn(returnCopy(enabledConfig(secret))).AnyTimes()
	svc := newService(t, ctrl, repo)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	wrong := code[:5] + string('0'+(code[5]-'0'+1)%10)
	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		require.Equal(t, 1, tf.FailedAttempts)
		return nil
	})
	require.NotNil(t, svc.VerifyCode(context.Background(), "u1", wrong))
}

func TestEnableTwoFactorConsumesTheSetupStep(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockTwoFactorRepository(ctrl)
	cfg := enabledConfig(newSecret(t))
	cfg.Enabled, cfg.Verified = false, false
	repo.EXPECT().GetByUserID(gomock.Any(), "u1").DoAndReturn(returnCopy(cfg)).AnyTimes()
	svc := newService(t, ctrl, repo)

	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		require.True(t, tf.Enabled)
		require.Equal(t, time.Now().Unix()/totpPeriod, tf.LastUsedStep)
		return nil
	})
	require.Nil(t, svc.EnableTwoFactor(context.Background(), "u1"))
}

func TestVerifyCodeManualAcceptsAdjacentStepsOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := newService(t, ctrl, mocks.NewMockTwoFactorRepository(ctrl))
	secret := newSecret(t)
	now := time.Now()
	for _, offset := range []time.Duration{-totpPeriod * time.Second, 0, totpPeriod * time.Second} {
		code, err := totp.GenerateCode(secret, now.Add(offset))
		require.NoError(t, err)
		require.Nil(t, svc.VerifyCodeManual(context.Background(), secret, code), "offset %v", offset)
	}
	far, err := totp.GenerateCode(secret, now.Add(3*totpPeriod*time.Second))
	require.NoError(t, err)
	require.NotNil(t, svc.VerifyCodeManual(context.Background(), secret, far))
}

func newServiceWithBackups(t *testing.T, ctrl *gomock.Controller, repo models.TwoFactorRepository, backups models.BackupCodeRepository) services.TwoFactorService {
	t.Helper()
	store := mocks.NewMockTwoFactorStorage(ctrl)
	store.EXPECT().TwoFactor().Return(repo).AnyTimes()
	store.EXPECT().BackupCodes().Return(backups).AnyTimes()
	// The lowest bcrypt cost keeps hashing eight codes fast under -race.
	fastHashing := security.NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:   "test-secret-key-for-unit-tests!!",
		EncryptionKey:  "test-encryption-key-for-tests!!",
		HashSaltLength: 4,
	})
	deps := config.ModuleDependencies{
		Storage:         &types.StorageSet{TwoFactorStore: store},
		Config:          testutil.TestConfig(),
		Logger:          quietLogger{},
		SecurityManager: fastHashing,
	}
	return services.NewTwoFactorService(deps, "GoAuth", 8, 8)
}

// fakeTwoFactorStore keeps one configuration and applies updates, so a
// sequence of verifications sees the state earlier ones persisted.
type fakeTwoFactorStore struct {
	models.TwoFactorRepository
	cfg models.TwoFactor
}

func (f *fakeTwoFactorStore) GetByUserID(context.Context, string) (*models.TwoFactor, error) {
	c := f.cfg
	return &c, nil
}

func (f *fakeTwoFactorStore) Update(_ context.Context, tf *models.TwoFactor) error {
	f.cfg = *tf
	return nil
}

func TestVerifyCodeLocksAfterRepeatedFailures(t *testing.T) {
	ctrl := gomock.NewController(t)
	secret := newSecret(t)
	store := &fakeTwoFactorStore{cfg: *enabledConfig(secret)}
	svc := newService(t, ctrl, store)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	wrong := code[:5] + string('0'+(code[5]-'0'+1)%10)
	for i := 1; i <= 5; i++ {
		authErr := svc.VerifyCode(context.Background(), "u1", wrong)
		require.NotNil(t, authErr, "wrong attempt %d", i)
		require.Equal(t, i, store.cfg.FailedAttempts)
	}
	require.NotNil(t, store.cfg.LockedUntil, "five failures must lock two-factor verification")
	require.True(t, store.cfg.LockedUntil.After(time.Now()))

	authErr := svc.VerifyCode(context.Background(), "u1", code)
	require.NotNil(t, authErr, "the correct code must be refused while locked")
	require.Equal(t, types.NewAccountLockedError().Code, authErr.Code)
}

func TestSaveTwoFactorConfigEncryptsTheSecretAtRest(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockTwoFactorRepository(ctrl)
	svc := newService(t, ctrl, repo)
	secret := newSecret(t)

	var stored *models.TwoFactor
	repo.EXPECT().GetByUserID(gomock.Any(), "u1").Return(nil, models.ErrNotFound)
	repo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tf *models.TwoFactor) error {
		copy := *tf
		stored = &copy
		return nil
	})
	require.Nil(t, svc.SaveTwoFactorConfig(context.Background(), &models.TwoFactor{UserID: "u1", Secret: secret, Method: "totp"}))
	require.NotNil(t, stored)
	require.NotEqual(t, secret, stored.Secret, "the TOTP secret must not be stored in plaintext")
	require.True(t, strings.HasPrefix(stored.Secret, "v1."), "stored secret %q is not a versioned ciphertext", stored.Secret)

	repo.EXPECT().GetByUserID(gomock.Any(), "u1").Return(stored, nil)
	loaded, authErr := svc.GetTwoFactorConfig(context.Background(), "u1")
	require.Nil(t, authErr)
	require.Equal(t, secret, loaded.Secret, "reading the configuration decrypts the secret")
}

func TestBackupCodesAreHashedAndSingleUse(t *testing.T) {
	ctrl := gomock.NewController(t)
	backups := mocks.NewMockBackupCodeRepository(ctrl)
	svc := newServiceWithBackups(t, ctrl, mocks.NewMockTwoFactorRepository(ctrl), backups)
	ctx := context.Background()

	plain, authErr := svc.GenerateBackupCodes(ctx, "u1")
	require.Nil(t, authErr)
	require.Len(t, plain, 8)
	seen := map[string]bool{}
	for _, code := range plain {
		require.Regexp(t, `^[A-Z0-9]{4}-[A-Z0-9]{4}$`, code)
		require.False(t, seen[code], "backup codes must be unique")
		seen[code] = true
	}

	var stored []*models.BackupCode
	backups.EXPECT().DeleteByUserID(ctx, "u1").Return(nil)
	backups.EXPECT().CreateBatch(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, codes []*models.BackupCode) error {
		stored = codes
		return nil
	})
	require.Nil(t, svc.SaveBackupCodes(ctx, "u1", plain))
	require.Len(t, stored, len(plain))
	for i, bc := range stored {
		require.NotEqual(t, plain[i], bc.Code, "backup codes must be stored hashed")
	}

	unused := func() []*models.BackupCode {
		var out []*models.BackupCode
		for _, bc := range stored {
			if !bc.Used {
				out = append(out, bc)
			}
		}
		return out
	}
	backups.EXPECT().GetUnusedByUserID(ctx, "u1").DoAndReturn(func(context.Context, string) ([]*models.BackupCode, error) { return unused(), nil }).AnyTimes()
	backups.EXPECT().MarkUsed(ctx, stored[0].ID).DoAndReturn(func(context.Context, string) error {
		stored[0].Used = true
		return nil
	})
	require.Nil(t, svc.UseBackupCode(ctx, "u1", plain[0]))
	require.NotNil(t, svc.UseBackupCode(ctx, "u1", plain[0]), "a used backup code must be refused")

	// A concurrent submission consumed the code between lookup and update.
	backups.EXPECT().MarkUsed(ctx, stored[1].ID).Return(models.ErrConflict)
	authErr = svc.UseBackupCode(ctx, "u1", plain[1])
	require.NotNil(t, authErr)
	require.Equal(t, types.NewTwoFactorInvalidError().Code, authErr.Code, "a lost race is an invalid code, not a server error")
}

func TestGenerateSecretProvisionsAValidAuthenticator(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := newService(t, ctrl, mocks.NewMockTwoFactorRepository(ctrl))

	secret, url, authErr := svc.GenerateSecret(context.Background(), "u1@example.com")
	require.Nil(t, authErr)
	require.NotEmpty(t, secret)
	require.Contains(t, url, "otpauth://totp/")
	require.Contains(t, url, "issuer=GoAuth")
	require.Contains(t, url, "u1@example.com")

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.Nil(t, svc.VerifyCodeManual(context.Background(), secret, code))
}
