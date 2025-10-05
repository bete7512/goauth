package resilience

import (
	"errors"
	"math/rand"
	"time"
)

// RetryWithBackoff retries a function with exponential backoff + jitter
func RetryWithBackoff(attempts int, initialDelay time.Duration, fn func() error) error {
	delay := initialDelay
	for i := 0; i < attempts; i++ {
		err := fn()
		if err == nil {
			return nil
		}

		// last attempt, return error
		if i == attempts-1 {
			return err
		}

		// add jitter
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		time.Sleep(delay + jitter)

		// exponential backoff
		delay *= 2
	}
	return errors.New("max retries reached")
}
