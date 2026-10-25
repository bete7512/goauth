package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	services "github.com/bete7512/goauth/internal/modules/twofactor/services"
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
