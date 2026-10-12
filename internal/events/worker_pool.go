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
	mu         sync.Mutex
	started    bool
	closed     bool
	workerCtx  context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	logger     logger.Logger
	dlq        *DeadLetterQueue
}

// NewWorkerPool creates a worker pool with specified number of workers.
// The DLQ parameter is optional — pass nil to disable dead letter queue.
// Construction starts no goroutines. SetDispatcher starts consumption.
func NewWorkerPool(workers int, queueSize int, log logger.Logger, dlq *DeadLetterQueue) *WorkerPool {
	if workers <= 0 {
		workers = 10 // Default
	}
	if queueSize <= 0 {
		queueSize = 1000 // Default
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	wp := &WorkerPool{workerCtx: workerCtx, cancel: cancel,
		workers:    workers,
		eventQueue: make(chan *types.Event, queueSize),
		stopChan:   make(chan struct{}),
		done:       make(chan struct{}),
		logger:     log,
		dlq:        dlq,
	}

	return wp
}

// SetDispatcher sets the callback invoked for each event.
// Must be called before events are submitted (called by DefaultAsyncBackend.Subscribe).
func (wp *WorkerPool) SetDispatcher(dispatcher types.EventDispatcher) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if wp.closed || wp.started || dispatcher == nil {
		return
	}
	wp.dispatcher = dispatcher
	wp.started = true
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker processes events from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for event := range wp.eventQueue {
		if event == nil || wp.dispatcher == nil {
			continue
		}
		wp.dispatcher(wp.workerCtx, event)
	}
}

// Submit adds an event to the queue (non-blocking).
// Returns ErrQueueFull if the queue is at capacity — the event is sent to the DLQ.
func (wp *WorkerPool) Submit(ctx context.Context, event *types.Event) error {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if wp.closed {
		return ErrClosed
	}
	if event == nil {
		return fmt.Errorf("nil event")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
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
	_ = wp.Shutdown(context.Background())
}

// Shutdown rejects new events and drains accepted work. A deadline limits the
// wait; handlers already running must cooperate with their own cancellation.
func (wp *WorkerPool) Shutdown(ctx context.Context) error {
	wp.stopOnce.Do(func() {
		wp.mu.Lock()
		wp.closed = true
		close(wp.stopChan)
		close(wp.eventQueue)
		if !wp.started {
			for event := range wp.eventQueue {
				if wp.dlq != nil {
					wp.dlq.Add(event, ErrClosed)
				}
			}
		}
		wp.mu.Unlock()
		go func() { wp.wg.Wait(); close(wp.done) }()
	})
	select {
	case <-wp.done:
		wp.cancel()
		return nil
	case <-ctx.Done():
		wp.cancel()
		return ctx.Err()
	}
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
var ErrClosed = fmt.Errorf("event backend is closed")
