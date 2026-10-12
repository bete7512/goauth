package operation

import (
	"context"
	"errors"
	"fmt"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"time"
)

type deferredEvent struct {
	kind types.EventType
	data interface{}
}
type transactionEvents struct {
	types.EventBus
	pending []deferredEvent
	outbox  types.OutboxStore
	failure error
}

func (b *transactionEvents) EmitAsync(ctx context.Context, kind types.EventType, data interface{}) error {
	if b.outbox != nil {
		event := &types.Event{ID: uuid.NewString(), SchemaVersion: 1, RealmID: "default", Type: kind, Data: data, CreatedAt: time.Now().UTC()}
		envelope, err := event.Envelope()
		if err != nil {
			b.failure = errors.Join(b.failure, err)
			return err
		}
		err = b.outbox.AppendEvent(ctx, envelope)
		b.failure = errors.Join(b.failure, err)
		return err
	}
	b.pending = append(b.pending, deferredEvent{kind: kind, data: data})
	return nil
}

// Run binds feature repositories and events to one operation. SQL callbacks
// must use the supplied dependencies; external calls belong outside the tx.
func Run[T any](ctx context.Context, deps config.ModuleDependencies, fn func(config.ModuleDependencies) (T, *types.GoAuthError)) (T, *types.GoAuthError) {
	var result T
	store, ok := deps.Storage.(types.TransactionalStorage)
	if !ok {
		return result, types.NewInternalError("operation requires colocated transactional storage")
	}
	events := &transactionEvents{EventBus: deps.Events}
	var authErr *types.GoAuthError
	err := store.WithTransaction(ctx, func(tx types.Storage) error {
		bound := deps
		bound.Storage = tx
		bound.Events = events
		if deps.Config.DurableEvents {
			var ok bool
			events.outbox, ok = tx.(types.OutboxStore)
			if !ok {
				return fmt.Errorf("transactional outbox unavailable")
			}
		}
		result, authErr = fn(bound)
		if authErr != nil {
			return authErr
		}
		return events.failure
	})
	if authErr != nil {
		return result, authErr
	}
	if err != nil {
		return result, types.NewInternalError("security operation failed").Wrap(err)
	}
	for _, event := range events.pending {
		if deps.Events != nil {
			_ = deps.Events.EmitAsync(ctx, event.kind, event.data)
		}
	}
	return result, nil
}
