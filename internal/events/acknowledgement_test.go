package events_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

type acknowledgingBackend struct {
	dispatch func(context.Context, *types.Event) error
}

func (b *acknowledgingBackend) Name() string { return "contract" }
func (b *acknowledgingBackend) Close() error { return nil }
func (b *acknowledgingBackend) Subscribe(context.Context, types.EventDispatcher) error {
	return errors.New("legacy acknowledgement path used")
}
func (b *acknowledgingBackend) SubscribeAcknowledged(_ context.Context, handler func(context.Context, *types.Event) error) error {
	b.dispatch = handler
	return nil
}
func (b *acknowledgingBackend) Publish(ctx context.Context, _ types.EventType, event *types.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	envelope, err := event.Envelope()
	if err != nil {
		return err
	}
	restored, err := envelope.Event()
	if err != nil {
		return err
	}
	return b.dispatch(ctx, restored)
}

func TestAcknowledgementPreservesFailureAndMetadata(t *testing.T) {
	backend := &acknowledgingBackend{}
	bus := events.NewEventBusWithBackend(nil, backend)
	t.Cleanup(func() { require.NoError(t, bus.Close()) })
	adapter := events.NewEventBusAdapter(bus)
	failure := errors.New("subscriber unavailable")
	var seenID string
	adapter.Subscribe(types.EventAfterOAuthLogin, types.EventHandler(func(_ context.Context, event *types.Event) error {
		require.Equal(t, 1, event.SchemaVersion)
		require.Equal(t, "default", event.RealmID)
		require.NotEmpty(t, event.ID)
		require.WithinDuration(t, time.Now(), event.CreatedAt, time.Second)
		seenID = event.ID
		data, ok := types.EventDataAs[*types.OAuthLoginEventData](event)
		require.True(t, ok)
		require.Equal(t, "user", data.User.ID)
		require.Empty(t, data.User.PasswordHash)
		require.Empty(t, data.ProviderAccessToken)
		require.Empty(t, data.ProviderRefreshToken)
		return failure
	}))
	require.NoError(t, bus.Start(context.Background()))
	err := adapter.EmitAsync(context.Background(), types.EventAfterOAuthLogin, &types.OAuthLoginEventData{User: &models.User{ID: "user", PasswordHash: "secret hash"}, ProviderAccessToken: "secret access", ProviderRefreshToken: "secret refresh"})
	require.ErrorIs(t, err, failure, "a durable backend must see processing failure before acknowledgement")
	require.NotEmpty(t, seenID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, adapter.EmitAsync(ctx, types.EventAfterOAuthLogin, &types.OAuthLoginEventData{}), context.Canceled)
}
