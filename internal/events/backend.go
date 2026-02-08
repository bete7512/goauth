package events

import (
	"context"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// DefaultAsyncBackend uses the built-in worker pool with retry and DLQ support.
type DefaultAsyncBackend struct {
	workerPool *WorkerPool
	dlq        *DeadLetterQueue
	logger     logger.Logger
}

// NewDefaultAsyncBackend creates a new worker pool backend with DLQ enabled.
func NewDefaultAsyncBackend(workers, queueSize int, log logger.Logger) *DefaultAsyncBackend {
	dlq := NewDeadLetterQueue(1000, log)
	return &DefaultAsyncBackend{
		workerPool: NewWorkerPool(workers, queueSize, log, dlq),
		dlq:        dlq,
		logger:     log,
	}
}

// Publish submits event to worker pool
func (b *DefaultAsyncBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
	// Worker pool doesn't need eventType since it's in the event
	// This is handled by EventBus calling handler directly
	return nil
}

// Close stops the worker pool
func (b *DefaultAsyncBackend) Close() error {
	b.workerPool.Stop()
	return nil
}

// Name returns backend name
func (b *DefaultAsyncBackend) Name() string {
	return "worker-pool"
}

// SubmitJob submits a job to worker pool (used by EventBus).
// The retryPolicy is passed per-handler from the subscription options.
func (b *DefaultAsyncBackend) SubmitJob(ctx context.Context, handler types.EventHandler, event *types.Event, retryPolicy *types.RetryPolicy) error {
	return b.workerPool.Submit(ctx, handler, event, retryPolicy)
}

// QueueStats returns queue statistics
func (b *DefaultAsyncBackend) QueueStats() (length, capacity int) {
	return b.workerPool.QueueLength(), b.workerPool.QueueCapacity()
}

// DLQ returns the dead letter queue for inspection.
func (b *DefaultAsyncBackend) DLQ() *DeadLetterQueue {
	return b.dlq
}
