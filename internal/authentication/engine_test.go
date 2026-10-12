package authentication_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/authentication"
	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*authentication.Engine, *store.GormStorage, *models.User) {
	t.Helper()
	s, err := store.NewStorage(store.Config{Dialect: types.DialectTypeSqlite, DSN: "file:" + uuid.NewString() + "?mode=memory&cache=shared", MaxOpenConns: 1, MaxIdleConns: 1})
	require.NoError(t, err)
	a, err := auth.New(&config.Config{Storage: s, Security: types.SecurityConfig{JwtSecretKey: "authentication-test-signing-secret", EncryptionKey: "authentication-test-encryption-key"}, Migration: config.MigrationConfig{Auto: true}})
	require.NoError(t, err)
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	cfg := a.Config()
	user := &models.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Active: true, EmailVerified: true}
	require.NoError(t, s.Core().Users().Create(context.Background(), user))
	registry := interceptor.NewRegistry()
	for _, factor := range []types.LoginChallengeType{types.ChallengeTwoFactor, types.ChallengeOrgSelect} {
		registry.Register(string(factor), func(ctx context.Context, p *types.InterceptParams) (*types.InterceptResult, error) {
			if p.Phase != types.PhaseLogin {
				return &types.InterceptResult{}, nil
			}
			return &types.InterceptResult{Challenge: &types.LoginChallenge{Type: factor}}, nil
		}, 10)
	}
	return &authentication.Engine{Store: s, Config: cfg, Security: security.NewSecurityManager(cfg.Security), Tokens: s.Core().Tokens(), Interceptors: registry}, s, user
}

func TestComposableSingleUseContinuation(t *testing.T) {
	e, _, user := fixture(t)
	ctx := context.Background()
	result, authErr := e.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "password"})
	require.Nil(t, authErr)
	require.Equal(t, types.ChallengeRequired, result.Status)
	require.Empty(t, result.AccessToken)
	require.Len(t, result.Challenges, 2)
	first := result.Challenges[0].Data["temp_token"].(string)
	partial, authErr := e.Resume(ctx, first, types.ChallengeTwoFactor)
	require.Nil(t, authErr)
	require.Equal(t, types.ChallengeRequired, partial.Status)
	require.Empty(t, partial.AccessToken)
	_, authErr = e.Resume(ctx, first, types.ChallengeOrgSelect)
	require.NotNil(t, authErr, "replaced continuation cannot be replayed")
	last := partial.Challenges[0].Data["temp_token"].(string)
	var wins atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := e.Resume(ctx, last, types.ChallengeOrgSelect)
			if err == nil && result.Status == types.Authenticated {
				wins.Add(1)
			}
		}()
	}
	group.Wait()
	require.Equal(t, int32(1), wins.Load())
}

type failingStore struct{ *store.GormStorage }
type failingTransaction struct {
	types.Storage
	types.OutboxStore
}

func (f failingTransaction) AppendEvent(context.Context, types.EventEnvelope) error {
	return errors.New("injected outbox failure")
}
func (f failingStore) WithTransaction(ctx context.Context, fn func(types.Storage) error) error {
	return f.GormStorage.WithTransaction(ctx, func(tx types.Storage) error {
		return fn(failingTransaction{Storage: tx, OutboxStore: tx.(types.OutboxStore)})
	})
}

func TestCompletionFailureRollsBackContinuationAndGrant(t *testing.T) {
	e, s, user := fixture(t)
	ctx := context.Background()
	result, err := e.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "password"})
	require.Nil(t, err)
	partial, err := e.Resume(ctx, result.Challenges[0].Data["temp_token"].(string), types.ChallengeTwoFactor)
	require.Nil(t, err)
	secret := partial.Challenges[0].Data["temp_token"].(string)
	e.Config.DurableEvents = true
	e.Store = failingStore{s}
	_, err = e.Resume(ctx, secret, types.ChallengeOrgSelect)
	require.NotNil(t, err)
	record, storeErr := s.Core().Tokens().FindByToken(ctx, e.Security.HashRefreshToken(secret))
	require.NoError(t, storeErr)
	require.False(t, record.Used)
	e.Store = s
	completed, err := e.Resume(ctx, secret, types.ChallengeOrgSelect)
	require.Nil(t, err)
	require.NotEmpty(t, completed.RefreshToken)
	batch, storeErr := s.ClaimEvents(ctx, "test", 10, time.Minute)
	require.NoError(t, storeErr)
	require.Len(t, batch, 1)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(batch[0].Envelope.Payload, &payload))
	require.Equal(t, user.ID, payload["user_id"])
}
