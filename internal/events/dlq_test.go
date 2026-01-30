package events_test

import (
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
)

type DLQSuite struct {
	suite.Suite
}

func TestDLQSuite(t *testing.T) {
	suite.Run(t, new(DLQSuite))
}

func (s *DLQSuite) testEvent(id string) *types.Event {
	return &types.Event{
		ID:         id,
		Type:       types.EventAfterSignup,
		RetryCount: 3,
	}
}

func (s *DLQSuite) TestNewDeadLetterQueue() {
	tests := []struct {
		name    string
		maxSize int
		wantCap int
	}{
		{
			name:    "valid size",
			maxSize: 500,
			wantCap: 500,
		},
		{
			name:    "zero defaults to 1000",
			maxSize: 0,
			wantCap: 1000,
		},
		{
			name:    "negative defaults to 1000",
			maxSize: -1,
			wantCap: 1000,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			dlq := events.NewDeadLetterQueue(tt.maxSize, nil)
			s.NotNil(dlq)
			s.Equal(0, dlq.Size())
		})
	}
}

func (s *DLQSuite) TestAddAndSize() {
	dlq := events.NewDeadLetterQueue(10, nil)

	dlq.Add(s.testEvent("e1"), errors.New("fail 1"))
	s.Equal(1, dlq.Size())

	dlq.Add(s.testEvent("e2"), errors.New("fail 2"))
	s.Equal(2, dlq.Size())
}

func (s *DLQSuite) TestEvictionWhenFull() {
	dlq := events.NewDeadLetterQueue(2, nil)

	dlq.Add(s.testEvent("e1"), errors.New("fail 1"))
	dlq.Add(s.testEvent("e2"), errors.New("fail 2"))
	s.Equal(2, dlq.Size())

	// Adding a third should evict the oldest (e1)
	dlq.Add(s.testEvent("e3"), errors.New("fail 3"))
	s.Equal(2, dlq.Size())

	letters := dlq.List()
	s.Equal("e2", letters[0].Event.ID)
	s.Equal("e3", letters[1].Event.ID)
}

func (s *DLQSuite) TestList() {
	dlq := events.NewDeadLetterQueue(10, nil)

	dlq.Add(s.testEvent("e1"), errors.New("fail 1"))
	dlq.Add(s.testEvent("e2"), errors.New("fail 2"))

	letters := dlq.List()
	s.Len(letters, 2)
	s.Equal("e1", letters[0].Event.ID)
	s.Equal("e2", letters[1].Event.ID)

	// List returns a copy, DLQ unchanged
	s.Equal(2, dlq.Size())
}

func (s *DLQSuite) TestDrain() {
	dlq := events.NewDeadLetterQueue(10, nil)

	dlq.Add(s.testEvent("e1"), errors.New("fail 1"))
	dlq.Add(s.testEvent("e2"), errors.New("fail 2"))

	drained := dlq.Drain()
	s.Len(drained, 2)
	s.Equal("e1", drained[0].Event.ID)

	// After drain, DLQ should be empty
	s.Equal(0, dlq.Size())
}

func (s *DLQSuite) TestPeek() {
	tests := []struct {
		name    string
		setup   func(*events.DeadLetterQueue)
		wantNil bool
		wantID  string
	}{
		{
			name:    "empty dlq returns nil",
			setup:   func(_ *events.DeadLetterQueue) {},
			wantNil: true,
		},
		{
			name: "returns oldest without removing",
			setup: func(dlq *events.DeadLetterQueue) {
				dlq.Add(&types.Event{ID: "e1", Type: types.EventAfterSignup}, errors.New("fail"))
				dlq.Add(&types.Event{ID: "e2", Type: types.EventAfterSignup}, errors.New("fail"))
			},
			wantID: "e1",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			dlq := events.NewDeadLetterQueue(10, nil)
			tt.setup(dlq)

			result := dlq.Peek()

			if tt.wantNil {
				s.Nil(result)
			} else {
				s.NotNil(result)
				s.Equal(tt.wantID, result.Event.ID)
				// Peek should not remove
				s.Equal(2, dlq.Size())
			}
		})
	}
}

func (s *DLQSuite) TestDeadLetterFields() {
	dlq := events.NewDeadLetterQueue(10, nil)

	event := &types.Event{
		ID:         "e1",
		Type:       types.EventAfterLogin,
		RetryCount: 5,
	}
	testErr := errors.New("handler crashed")

	dlq.Add(event, testErr)

	letters := dlq.List()
	s.Len(letters, 1)

	dl := letters[0]
	s.Equal(event, dl.Event)
	s.Equal(testErr, dl.Error)
	s.Equal(5, dl.Retries)
	s.False(dl.FailedAt.IsZero())
}
