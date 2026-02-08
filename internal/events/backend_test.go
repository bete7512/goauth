package events_test

import (
	"testing"

	"github.com/bete7512/goauth/internal/events"
	"github.com/stretchr/testify/suite"
)

type BackendSuite struct {
	suite.Suite
}

func TestBackendSuite(t *testing.T) {
	suite.Run(t, new(BackendSuite))
}

func (s *BackendSuite) TestDefaultAsyncBackendName() {
	backend := events.NewDefaultAsyncBackend(2, 10, nil)
	defer backend.Close()

	s.Equal("worker-pool", backend.Name())
}

func (s *BackendSuite) TestDefaultAsyncBackendClose() {
	backend := events.NewDefaultAsyncBackend(2, 10, nil)
	err := backend.Close()
	s.NoError(err)
}

func (s *BackendSuite) TestDefaultAsyncBackendDLQ() {
	backend := events.NewDefaultAsyncBackend(2, 10, nil)
	defer backend.Close()

	dlq := backend.DLQ()
	s.NotNil(dlq)
	s.Equal(0, dlq.Size())
}

func (s *BackendSuite) TestDefaultAsyncBackendQueueStats() {
	backend := events.NewDefaultAsyncBackend(2, 50, nil)
	defer backend.Close()

	length, capacity := backend.QueueStats()
	s.Equal(0, length)
	s.Equal(50, capacity)
}
