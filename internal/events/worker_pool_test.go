package events_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
)

type WorkerPoolSuite struct {
	suite.Suite
}

func TestWorkerPoolSuite(t *testing.T) {
	suite.Run(t, new(WorkerPoolSuite))
}

func (s *WorkerPoolSuite) TestSubmitAndExecute() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(2, 100, nil, dlq)
	defer wp.Stop()

	done := make(chan struct{})
	handler := func(_ context.Context, event *types.Event) error {
		close(done)
		return nil
	}

	event := &types.Event{ID: "e1", Type: types.EventAfterSignup}
	err := wp.Submit(context.Background(), handler, event, nil)
	s.NoError(err)

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		s.Fail("handler was not called within timeout")
	}
}

func (s *WorkerPoolSuite) TestRetrySucceedsAfterFailures() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(1, 100, nil, dlq)
	defer wp.Stop()

	var attempts int32
	done := make(chan struct{})

	handler := func(_ context.Context, event *types.Event) error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return errors.New("transient error")
		}
		close(done)
		return nil
	}

	policy := &types.RetryPolicy{
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	event := &types.Event{ID: "retry-ok", Type: types.EventAfterLogin}
	err := wp.Submit(context.Background(), handler, event, policy)
	s.NoError(err)

	select {
	case <-done:
		s.GreaterOrEqual(atomic.LoadInt32(&attempts), int32(3))
		s.Equal(0, dlq.Size(), "should not be in DLQ on success")
	case <-time.After(5 * time.Second):
		s.Fail("handler did not succeed within timeout")
	}
}

func (s *WorkerPoolSuite) TestRetryExhaustedSendsToDLQ() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(1, 100, nil, dlq)
	defer wp.Stop()

	done := make(chan struct{})
	handler := func(_ context.Context, event *types.Event) error {
		if event.RetryCount >= 2 {
			defer func() {
				select {
				case <-done:
				default:
					close(done)
				}
			}()
		}
		return errors.New("permanent failure")
	}

	policy := &types.RetryPolicy{
		MaxRetries:        2,
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        50 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	event := &types.Event{ID: "retry-fail", Type: types.EventAfterLogin}
	err := wp.Submit(context.Background(), handler, event, policy)
	s.NoError(err)

	select {
	case <-done:
		// Give a tiny window for DLQ.Add to complete
		time.Sleep(50 * time.Millisecond)
		s.Equal(1, dlq.Size(), "failed event should be in DLQ")
	case <-time.After(5 * time.Second):
		s.Fail("handler did not exhaust retries within timeout")
	}
}

func (s *WorkerPoolSuite) TestNoRetryFailureSendsToDLQ() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(1, 100, nil, dlq)
	defer wp.Stop()

	done := make(chan struct{})
	handler := func(_ context.Context, event *types.Event) error {
		defer close(done)
		return errors.New("immediate failure")
	}

	event := &types.Event{ID: "no-retry", Type: types.EventAfterSignup}
	err := wp.Submit(context.Background(), handler, event, nil)
	s.NoError(err)

	select {
	case <-done:
		time.Sleep(50 * time.Millisecond)
		s.Equal(1, dlq.Size(), "failed event with no retry should go to DLQ")
	case <-time.After(2 * time.Second):
		s.Fail("handler was not called within timeout")
	}
}

func (s *WorkerPoolSuite) TestQueueFullSendsToDLQ() {
	dlq := events.NewDeadLetterQueue(100, nil)
	// 1 worker, queue size 1 — fill the queue, then next submit overflows
	wp := events.NewWorkerPool(1, 1, nil, dlq)
	defer wp.Stop()

	blocker := make(chan struct{})
	blockingHandler := func(_ context.Context, event *types.Event) error {
		<-blocker
		return nil
	}

	// First job: blocks the worker
	wp.Submit(context.Background(), blockingHandler, &types.Event{ID: "block", Type: types.EventAfterSignup}, nil)
	time.Sleep(50 * time.Millisecond) // let worker pick it up

	// Second job: fills the queue buffer
	wp.Submit(context.Background(), blockingHandler, &types.Event{ID: "fill", Type: types.EventAfterSignup}, nil)

	// Third job: queue is full, should go to DLQ
	err := wp.Submit(context.Background(), blockingHandler, &types.Event{ID: "overflow", Type: types.EventAfterSignup}, nil)
	s.Error(err)
	s.Equal(1, dlq.Size())

	close(blocker)
}

func (s *WorkerPoolSuite) TestQueueLengthAndCapacity() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(2, 50, nil, dlq)
	defer wp.Stop()

	s.Equal(50, wp.QueueCapacity())
	s.Equal(0, wp.QueueLength())
}

func (s *WorkerPoolSuite) TestStopGraceful() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(2, 100, nil, dlq)

	var executed int32
	handler := func(_ context.Context, event *types.Event) error {
		atomic.AddInt32(&executed, 1)
		return nil
	}

	for i := 0; i < 5; i++ {
		wp.Submit(context.Background(), handler, &types.Event{ID: "s", Type: types.EventAfterSignup}, nil)
	}

	wp.Stop()
	// After stop, workers should have processed submitted jobs
	s.GreaterOrEqual(atomic.LoadInt32(&executed), int32(1))
}

func (s *WorkerPoolSuite) TestDLQAccessor() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(1, 10, nil, dlq)
	defer wp.Stop()

	s.Equal(dlq, wp.DLQ())
}

func (s *WorkerPoolSuite) TestNilDLQ() {
	wp := events.NewWorkerPool(1, 10, nil, nil)
	defer wp.Stop()

	s.Nil(wp.DLQ())
}
