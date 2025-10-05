package resilience

import (
	"sync"
	"time"
)

type CircuitState int

const (
	Closed   CircuitState = iota // normal
	Open                         // failing, rejecting calls
	HalfOpen                     // testing if recovery is possible
)

type CircuitBreaker struct {
	FailureThreshold int           // how many failures before opening
	ResetTimeout     time.Duration // how long to wait before moving to HalfOpen

	mu          sync.Mutex
	failures    int
	state       CircuitState
	lastFailure time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		FailureThreshold: failureThreshold,
		ResetTimeout:     resetTimeout,
		state:            Closed,
	}
}

// Allow checks if the call is allowed
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case Open:
		if time.Since(cb.lastFailure) > cb.ResetTimeout {
			cb.state = HalfOpen
			return true
		}
		return false
	case HalfOpen, Closed:
		return true
	default:
		return false
	}
}

// Success resets failures after a successful call
func (cb *CircuitBreaker) Success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = Closed
}

// Fail registers a failure
func (cb *CircuitBreaker) Fail() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.FailureThreshold {
		cb.state = Open
	}
}
