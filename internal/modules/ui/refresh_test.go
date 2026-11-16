package ui

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RefreshSuite struct {
	suite.Suite
}

func TestRefreshSuite(t *testing.T) {
	suite.Run(t, new(RefreshSuite))
}

func (s *RefreshSuite) TestSharesOneRefresh() {
	t := s.T()
	var group refreshGroup
	var calls atomic.Int32
	release := make(chan struct{})
	refresh := func() (types.AuthenticationResult, error) {
		calls.Add(1)
		<-release
		return types.AuthenticationResult{Status: types.Authenticated, AccessToken: "new"}, nil
	}

	var wg sync.WaitGroup
	results := make([]types.AuthenticationResult, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = group.do("refresh-token", refresh)
		}()
	}
	// Let every caller reach the group before the refresh finishes.
	assert.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load(), "one refresh for callers that arrived together")
	for _, result := range results {
		assert.Equal(t, "new", result.AccessToken)
	}

	// Nothing is remembered once the refresh is over.
	_, _ = group.do("refresh-token", func() (types.AuthenticationResult, error) {
		calls.Add(1)
		return types.AuthenticationResult{}, nil
	})
	assert.Equal(t, int32(2), calls.Load())
	assert.Empty(t, group.inFlight)
}

func (s *RefreshSuite) TestKeepsTokensApart() {
	t := s.T()
	var group refreshGroup
	a, _ := group.do("a", func() (types.AuthenticationResult, error) {
		return types.AuthenticationResult{AccessToken: "for-a"}, nil
	})
	b, _ := group.do("b", func() (types.AuthenticationResult, error) {
		return types.AuthenticationResult{AccessToken: "for-b"}, nil
	})
	assert.Equal(t, "for-a", a.AccessToken)
	assert.Equal(t, "for-b", b.AccessToken)
}
