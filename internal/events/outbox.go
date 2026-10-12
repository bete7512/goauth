package events

import (
	"context"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"time"
)

// DrainOutbox processes bounded batches. Failed deliveries retain their stable
// event ID for retry; a crashed worker's lease expires without losing work.
func (eb *EventBus) DrainOutbox(ctx context.Context, store types.OutboxStore) error {
	lease := uuid.NewString()
	batch, err := store.ClaimEvents(ctx, lease, 32, time.Minute)
	if err != nil {
		return err
	}
	for _, record := range batch {
		event, err := record.Envelope.Event()
		if err == nil {
			err = eb.dispatchAcknowledged(ctx, event)
		}
		if err != nil {
			delay := time.Second * time.Duration(min(record.Attempts, 60))
			if retryErr := store.RetryEvent(ctx, record.Envelope.ID, lease, time.Now().Add(delay)); retryErr != nil {
				return retryErr
			}
			continue
		}
		if err := store.AckEvent(ctx, record.Envelope.ID, lease); err != nil {
			return err
		}
	}
	return nil
}
