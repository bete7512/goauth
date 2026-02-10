package events_test

import (
	"context"
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

func (s *WorkerPoolSuite) TestSubmitAndDispatch() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(2, 100, nil, dlq)
	defer wp.Stop()

	done := make(chan struct{})
	wp.SetDispatcher(func(_ context.Context, event *types.Event) {
		s.Equal("e1", event.ID)
		close(done)
	})

	event := &types.Event{ID: "e1", Type: types.EventAfterSignup}
	err := wp.Submit(context.Background(), event)
	s.NoError(err)

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		s.Fail("dispatcher was not called within timeout")
	}
}

func (s *WorkerPoolSuite) TestSubmitWithoutDispatcherSkips() {
	dlq := events.NewDeadLetterQueue(100, nil)
	wp := events.NewWorkerPool(1, 100, nil, dlq)
	defer wp.Stop()

	// No dispatcher set — event should be silently skipped
	event := &types.Event{ID: "skip", Type: types.EventAfterSignup}
	err := wp.Submit(context.Background(), event)
	s.NoError(err)

	// Give worker time to process
	time.Sleep(50 * time.Millisecond)
	s.Equal(0, dlq.Size())
}

func (s *WorkerPoolSuite) TestQueueFullSendsToDLQ() {
	dlq := events.NewDeadLetterQueue(100, nil)
	// 1 worker, queue size 1 — fill the queue, then next submit overflows
	wp := events.NewWorkerPool(1, 1, nil, dlq)
	defer wp.Stop()

	blocker := make(chan struct{})
	wp.SetDispatcher(func(_ context.Context, event *types.Event) {
		<-blocker
	})

	// First event: blocks the worker
	wp.Submit(context.Background(), &types.Event{ID: "block", Type: types.EventAfterSignup})
	time.Sleep(50 * time.Millisecond) // let worker pick it up

	// Second event: fills the queue buffer
	wp.Submit(context.Background(), &types.Event{ID: "fill", Type: types.EventAfterSignup})

	// Third event: queue is full, should go to DLQ
	err := wp.Submit(context.Background(), &types.Event{ID: "overflow", Type: types.EventAfterSignup})
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
	wp.SetDispatcher(func(_ context.Context, event *types.Event) {
		atomic.AddInt32(&executed, 1)
	})

	for i := 0; i < 5; i++ {
		wp.Submit(context.Background(), &types.Event{ID: "s", Type: types.EventAfterSignup})
	}

	wp.Stop()
	// After stop, workers should have processed submitted events
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
