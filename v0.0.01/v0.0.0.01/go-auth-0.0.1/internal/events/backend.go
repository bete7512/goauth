package events

import (
	"context"
)

// AsyncBackend defines the interface for async event processing backends
// Users can provide custom implementations (Redis, RabbitMQ, Kafka, etc.)
type AsyncBackend interface {
	// Publish sends an event to the async backend
	Publish(ctx context.Context, eventType EventType, event *Event) error

	// Close gracefully shuts down the backend
	Close() error

	// Name returns the backend name for logging
	Name() string
}

// DefaultAsyncBackend uses the built-in worker pool
type DefaultAsyncBackend struct {
	workerPool *WorkerPool
	logger     Logger
}

// NewDefaultAsyncBackend creates a new worker pool backend
func NewDefaultAsyncBackend(workers, queueSize int, logger Logger) *DefaultAsyncBackend {
	return &DefaultAsyncBackend{
		workerPool: NewWorkerPool(workers, queueSize, logger),
		logger:     logger,
	}
}

// Publish submits event to worker pool
func (b *DefaultAsyncBackend) Publish(ctx context.Context, eventType EventType, event *Event) error {
	// Worker pool doesn't need eventType since it's in the job
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

// SubmitJob submits a job to worker pool (used by EventBus)
func (b *DefaultAsyncBackend) SubmitJob(ctx context.Context, handler Handler, event *Event) error {
	return b.workerPool.Submit(ctx, handler, event)
}

// QueueStats returns queue statistics
func (b *DefaultAsyncBackend) QueueStats() (length, capacity int) {
	return b.workerPool.QueueLength(), b.workerPool.QueueCapacity()
}
