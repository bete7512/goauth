package events

import (
	"context"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// DefaultAsyncBackend uses the built-in worker pool with DLQ support.
// Events are queued in a buffered channel and processed by goroutine workers
// via the dispatcher set through Subscribe.
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

// Publish submits an event to the worker pool queue.
func (b *DefaultAsyncBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
	return b.workerPool.Submit(ctx, event)
}

// Subscribe sets the dispatcher on the worker pool.
// Workers will call dispatcher(ctx, event) for each queued event.
func (b *DefaultAsyncBackend) Subscribe(ctx context.Context, dispatcher types.EventDispatcher) error {
	b.workerPool.SetDispatcher(dispatcher)
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

// QueueStats returns queue statistics
func (b *DefaultAsyncBackend) QueueStats() (length, capacity int) {
	return b.workerPool.QueueLength(), b.workerPool.QueueCapacity()
}

// DLQ returns the dead letter queue for inspection.
func (b *DefaultAsyncBackend) DLQ() *DeadLetterQueue {
	return b.dlq
}
