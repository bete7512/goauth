package events_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
)

type EventBusSuite struct {
	suite.Suite
}

func TestEventBusSuite(t *testing.T) {
	suite.Run(t, new(EventBusSuite))
}

func (s *EventBusSuite) TestSubscribeAndHasHandlers() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	s.False(eb.HasHandlers(types.EventAfterSignup))

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, _ *types.Event) error {
		return nil
	})

	s.True(eb.HasHandlers(types.EventAfterSignup))
	s.False(eb.HasHandlers(types.EventAfterLogin))
}

func (s *EventBusSuite) TestUnsubscribe() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, _ *types.Event) error {
		return nil
	})
	s.True(eb.HasHandlers(types.EventAfterSignup))

	eb.Unsubscribe(types.EventAfterSignup)
	s.False(eb.HasHandlers(types.EventAfterSignup))
}

func (s *EventBusSuite) TestEmitSync() {
	tests := []struct {
		name        string
		eventType   types.EventType
		subscribe   bool
		handlerErr  error
		wantErr     bool
		wantCalled  bool
	}{
		{
			name:       "handler called successfully",
			eventType:  types.EventAfterSignup,
			subscribe:  true,
			wantCalled: true,
		},
		{
			name:       "handler returns error",
			eventType:  types.EventAfterSignup,
			subscribe:  true,
			handlerErr: errors.New("handler failed"),
			wantErr:    true,
			wantCalled: true,
		},
		{
			name:      "no handlers - no error",
			eventType: types.EventAfterSignup,
			subscribe: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			eb := events.NewEventBus(nil)
			defer eb.Close()

			var called bool
			if tt.subscribe {
				eb.Subscribe(tt.eventType, func(_ context.Context, event *types.Event) error {
					called = true
					s.Equal(tt.eventType, event.Type)
					s.NotEmpty(event.ID)
					return tt.handlerErr
				})
			}

			err := eb.EmitSync(context.Background(), tt.eventType, nil)

			if tt.wantErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
			s.Equal(tt.wantCalled, called)
		})
	}
}

func (s *EventBusSuite) TestEmitSyncPriorityOrder() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	var order []int

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, _ *types.Event) error {
		order = append(order, 1)
		return nil
	}, events.WithPriority(1))

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, _ *types.Event) error {
		order = append(order, 10)
		return nil
	}, events.WithPriority(10))

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, _ *types.Event) error {
		order = append(order, 5)
		return nil
	}, events.WithPriority(5))

	err := eb.EmitSync(context.Background(), types.EventAfterSignup, nil)
	s.NoError(err)

	// Higher priority first
	s.Equal([]int{10, 5, 1}, order)
}

func (s *EventBusSuite) TestEmitAsync() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	var called int32
	done := make(chan struct{})

	eb.Subscribe(types.EventAfterLogin, func(_ context.Context, event *types.Event) error {
		atomic.AddInt32(&called, 1)
		s.Equal(types.EventAfterLogin, event.Type)
		close(done)
		return nil
	})

	err := eb.EmitAsync(context.Background(), types.EventAfterLogin, nil)
	s.NoError(err)

	select {
	case <-done:
		s.Equal(int32(1), atomic.LoadInt32(&called))
	case <-time.After(2 * time.Second):
		s.Fail("async handler was not called within timeout")
	}
}

func (s *EventBusSuite) TestEmitAsyncNoHandlers() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	err := eb.EmitAsync(context.Background(), types.EventAfterSignup, nil)
	s.NoError(err)
}

func (s *EventBusSuite) TestEmitSyncEventFields() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	type testData struct{ Name string }
	payload := &testData{Name: "test-user"}

	eb.Subscribe(types.EventAfterSignup, func(_ context.Context, event *types.Event) error {
		s.Equal(types.EventAfterSignup, event.Type)
		s.NotEmpty(event.ID)
		s.False(event.CreatedAt.IsZero())
		s.IsType(&testData{}, event.Data)
		s.Equal("test-user", event.Data.(*testData).Name)
		return nil
	})

	err := eb.EmitSync(context.Background(), types.EventAfterSignup, payload)
	s.NoError(err)
}

func (s *EventBusSuite) TestClose() {
	eb := events.NewEventBus(nil)
	err := eb.Close()
	s.NoError(err)
}

func (s *EventBusSuite) TestDLQAccessor() {
	eb := events.NewEventBus(nil)
	defer eb.Close()

	// Default backend provides a DLQ
	dlq := eb.DLQ()
	s.NotNil(dlq)
}
