package events

import (
	"sync"
	"time"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// DeadLetter represents a failed event that exhausted all retries.
type DeadLetter struct {
	// Event is the original event that failed
	Event *types.Event

	// Error is the last error that caused the failure
	Error error

	// FailedAt is when the event was sent to the DLQ
	FailedAt time.Time

	// Retries is the number of retry attempts made
	Retries int
}

// DeadLetterQueue stores events that failed after exhausting all retries.
// It provides an in-memory buffer with a configurable max size.
// Events in the DLQ can be inspected, retried, or drained for external processing.
type DeadLetterQueue struct {
	mu      sync.RWMutex
	letters []DeadLetter
	maxSize int
	logger  logger.Logger
}

// NewDeadLetterQueue creates a DLQ with the given max size.
// When the DLQ is full, the oldest entries are evicted.
func NewDeadLetterQueue(maxSize int, log logger.Logger) *DeadLetterQueue {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &DeadLetterQueue{
		letters: make([]DeadLetter, 0, maxSize),
		maxSize: maxSize,
		logger:  log,
	}
}

// Add inserts a failed event into the DLQ.
// If the DLQ is full, the oldest entry is evicted.
func (dlq *DeadLetterQueue) Add(event *types.Event, err error) {
	dlq.mu.Lock()
	defer dlq.mu.Unlock()

	dl := DeadLetter{
		Event:    event,
		Error:    err,
		FailedAt: time.Now(),
		Retries:  event.RetryCount,
	}

	if len(dlq.letters) >= dlq.maxSize {
		// Evict oldest
		evicted := dlq.letters[0]
		dlq.letters = dlq.letters[1:]
		if dlq.logger != nil {
			dlq.logger.Warnf("DLQ full, evicting oldest entry (event=%s, id=%s)", evicted.Event.Type, evicted.Event.ID)
		}
	}

	dlq.letters = append(dlq.letters, dl)
}

// Size returns the current number of entries in the DLQ.
func (dlq *DeadLetterQueue) Size() int {
	dlq.mu.RLock()
	defer dlq.mu.RUnlock()
	return len(dlq.letters)
}

// List returns a copy of all dead letters in the DLQ.
func (dlq *DeadLetterQueue) List() []DeadLetter {
	dlq.mu.RLock()
	defer dlq.mu.RUnlock()

	result := make([]DeadLetter, len(dlq.letters))
	copy(result, dlq.letters)
	return result
}

// Drain removes and returns all dead letters from the DLQ.
// Use this for batch processing or external persistence.
func (dlq *DeadLetterQueue) Drain() []DeadLetter {
	dlq.mu.Lock()
	defer dlq.mu.Unlock()

	result := dlq.letters
	dlq.letters = make([]DeadLetter, 0, dlq.maxSize)
	return result
}

// Peek returns the oldest dead letter without removing it.
// Returns nil if the DLQ is empty.
func (dlq *DeadLetterQueue) Peek() *DeadLetter {
	dlq.mu.RLock()
	defer dlq.mu.RUnlock()

	if len(dlq.letters) == 0 {
		return nil
	}
	dl := dlq.letters[0]
	return &dl
}
