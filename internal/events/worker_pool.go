package events

import (
	"context"
	"fmt"
	"sync"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// WorkerPool manages a pool of workers for async event handling
// with retry logic and dead letter queue support.
type WorkerPool struct {
	workers  int
	jobQueue chan *job
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
	logger   logger.Logger
	dlq      *DeadLetterQueue
}

type job struct {
	ctx         context.Context
	handler     types.EventHandler
	event       *types.Event
	retryPolicy *types.RetryPolicy
}

// NewWorkerPool creates a worker pool with specified number of workers.
// The DLQ parameter is optional — pass nil to disable dead letter queue.
func NewWorkerPool(workers int, queueSize int, log logger.Logger, dlq *DeadLetterQueue) *WorkerPool {
	if workers <= 0 {
		workers = 10 // Default
	}
	if queueSize <= 0 {
		queueSize = 1000 // Default
	}

	wp := &WorkerPool{
		workers:  workers,
		jobQueue: make(chan *job, queueSize),
		stopChan: make(chan struct{}),
		logger:   log,
		dlq:      dlq,
	}

	// Start workers
	for i := 0; i < workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}

	return wp
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.stopChan:
			return
		case j := <-wp.jobQueue:
			if j == nil {
				continue
			}

			if j.retryPolicy != nil && j.retryPolicy.MaxRetries > 0 {
				// Process with retry logic
				processWithRetry(j.ctx, j.handler, j.event, *j.retryPolicy, wp.dlq, wp.logger)
			} else {
				// No retry — execute once, send to DLQ on failure
				if err := j.handler(j.ctx, j.event); err != nil {
					if wp.logger != nil {
						wp.logger.Errorf("Worker %d: handler error (event=%s, id=%s): %v", id, j.event.Type, j.event.ID, err)
					}
					if wp.dlq != nil {
						wp.dlq.Add(j.event, err)
					}
				}
			}
		}
	}
}

// Submit adds a job to the queue (non-blocking with timeout).
// Pass a retryPolicy to enable retries for this specific job.
func (wp *WorkerPool) Submit(ctx context.Context, handler types.EventHandler, event *types.Event, retryPolicy *types.RetryPolicy) error {
	// Use background context for async job execution
	// This prevents context cancellation when HTTP request completes
	backgroundCtx := context.Background()

	j := &job{
		ctx:         backgroundCtx,
		handler:     handler,
		event:       event,
		retryPolicy: retryPolicy,
	}

	select {
	case wp.jobQueue <- j:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Queue is full — send to DLQ instead of silently dropping
		if wp.logger != nil {
			wp.logger.Warnf("Event queue full, event sent to DLQ (event=%s, id=%s)", event.Type, event.ID)
		}
		if wp.dlq != nil {
			wp.dlq.Add(event, ErrQueueFull)
		}
		return ErrQueueFull
	}
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	wp.stopOnce.Do(func() {
		close(wp.stopChan)
		wp.wg.Wait()
		close(wp.jobQueue)
	})
}

// QueueLength returns current queue length
func (wp *WorkerPool) QueueLength() int {
	return len(wp.jobQueue)
}

// QueueCapacity returns queue capacity
func (wp *WorkerPool) QueueCapacity() int {
	return cap(wp.jobQueue)
}

// DLQ returns the dead letter queue (may be nil if not configured)
func (wp *WorkerPool) DLQ() *DeadLetterQueue {
	return wp.dlq
}

var ErrQueueFull = fmt.Errorf("event queue is full")
