package events

import (
	"context"
	"fmt"
	"sync"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// WorkerPool manages a pool of workers for async event processing.
// Events are pulled from a buffered channel and dispatched via the
// registered EventDispatcher callback.
type WorkerPool struct {
	workers    int
	eventQueue chan *types.Event
	dispatcher types.EventDispatcher
	wg         sync.WaitGroup
	stopOnce   sync.Once
	stopChan   chan struct{}
	logger     logger.Logger
	dlq        *DeadLetterQueue
}

// NewWorkerPool creates a worker pool with specified number of workers.
// The DLQ parameter is optional — pass nil to disable dead letter queue.
// Workers start immediately but won't process events until SetDispatcher is called.
func NewWorkerPool(workers int, queueSize int, log logger.Logger, dlq *DeadLetterQueue) *WorkerPool {
	if workers <= 0 {
		workers = 10 // Default
	}
	if queueSize <= 0 {
		queueSize = 1000 // Default
	}

	wp := &WorkerPool{
		workers:    workers,
		eventQueue: make(chan *types.Event, queueSize),
		stopChan:   make(chan struct{}),
		logger:     log,
		dlq:        dlq,
	}

	// Start workers
	for i := 0; i < workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}

	return wp
}

// SetDispatcher sets the callback invoked for each event.
// Must be called before events are submitted (called by DefaultAsyncBackend.Subscribe).
func (wp *WorkerPool) SetDispatcher(dispatcher types.EventDispatcher) {
	wp.dispatcher = dispatcher
}

// worker processes events from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.stopChan:
			return
		case event := <-wp.eventQueue:
			if event == nil || wp.dispatcher == nil {
				continue
			}
			wp.dispatcher(context.Background(), event)
		}
	}
}

// Submit adds an event to the queue (non-blocking).
// Returns ErrQueueFull if the queue is at capacity — the event is sent to the DLQ.
func (wp *WorkerPool) Submit(ctx context.Context, event *types.Event) error {
	select {
	case wp.eventQueue <- event:
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
		close(wp.eventQueue)
	})
}

// QueueLength returns current queue length
func (wp *WorkerPool) QueueLength() int {
	return len(wp.eventQueue)
}

// QueueCapacity returns queue capacity
func (wp *WorkerPool) QueueCapacity() int {
	return cap(wp.eventQueue)
}

// DLQ returns the dead letter queue (may be nil if not configured)
func (wp *WorkerPool) DLQ() *DeadLetterQueue {
	return wp.dlq
}

var ErrQueueFull = fmt.Errorf("event queue is full")
