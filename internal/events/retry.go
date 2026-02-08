package events

import (
	"context"
	"time"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// processWithRetry executes a handler with exponential backoff retry.
// If all retries are exhausted, the event is sent to the dead letter queue.
func processWithRetry(
	ctx context.Context,
	handler types.EventHandler,
	event *types.Event,
	policy types.RetryPolicy,
	dlq *DeadLetterQueue,
	log logger.Logger,
) error {
	var lastErr error
	backoff := policy.InitialBackoff

	for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
		event.RetryCount = attempt

		lastErr = handler(ctx, event)
		if lastErr == nil {
			return nil
		}

		if log != nil {
			log.Warnf("Event handler failed (attempt %d/%d, event=%s): %v",
				attempt+1, policy.MaxRetries+1, event.Type, lastErr)
		}

		// Don't sleep after the last attempt
		if attempt < policy.MaxRetries {
			select {
			case <-ctx.Done():
				// Context cancelled, send to DLQ
				if dlq != nil {
					dlq.Add(event, lastErr)
				}
				return ctx.Err()
			case <-time.After(backoff):
			}

			// Exponential backoff
			backoff = time.Duration(float64(backoff) * policy.BackoffMultiplier)
			if backoff > policy.MaxBackoff {
				backoff = policy.MaxBackoff
			}
		}
	}

	// All retries exhausted — send to DLQ
	if dlq != nil {
		dlq.Add(event, lastErr)
		if log != nil {
			log.Errorf("Event sent to DLQ after %d retries (event=%s, id=%s): %v",
				policy.MaxRetries+1, event.Type, event.ID, lastErr)
		}
	}

	return lastErr
}
