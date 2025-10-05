package events

import (
	"context"
	"fmt"
	"sync"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// WorkerPool manages a pool of workers for async event handling
type WorkerPool struct {
	workers  int
	jobQueue chan *job
	wg       sync.WaitGroup
	stopOnce sync.Once
	stopChan chan struct{}
	logger   logger.Logger
}

type job struct {
	ctx     context.Context
	handler types.EventHandler
	event   *types.Event
}

// NewWorkerPool creates a worker pool with specified number of workers
func NewWorkerPool(workers int, queueSize int, log logger.Logger) *WorkerPool {
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
		case job := <-wp.jobQueue:
			if job != nil {
				if err := job.handler(job.ctx, job.event); err != nil {
					if wp.logger != nil {
						wp.logger.Error("Worker error", "worker_id", id, "error", err)
					}
				}
			}
		}
	}
}

// Submit adds a job to the queue (non-blocking with timeout)
func (wp *WorkerPool) Submit(ctx context.Context, handler types.EventHandler, event *types.Event) error {
	j := &job{
		ctx:     ctx,
		handler: handler,
		event:   event,
	}

	select {
	case wp.jobQueue <- j:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Queue is full, log and drop (or implement backpressure)
		if wp.logger != nil {
			wp.logger.Warn("Event queue full, dropping event", "type", event.Type)
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

var ErrQueueFull = fmt.Errorf("event queue is full")
