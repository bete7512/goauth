package types

import (
	"context"
	"time"
)

// OutboxStore belongs to the same transaction as the security mutation.
// Claim must conditionally lease rows; Ack/Retry require the current lease ID.
type OutboxStore interface {
	AppendEvent(context.Context, EventEnvelope) error
	ClaimEvents(context.Context, string, int, time.Duration) ([]OutboxEvent, error)
	AckEvent(context.Context, string, string) error
	RetryEvent(context.Context, string, string, time.Time) error
}

// OutboxEvent is a claimed outbox row: the event envelope and its delivery
// attempts so far.
type OutboxEvent struct {
	Envelope EventEnvelope
	Attempts int
}
