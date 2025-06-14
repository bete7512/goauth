package ratelimiter

import (
	"sync"
	"time"

	"github.com/bete7512/goauth/types"
)

type MemoryRateLimiter struct {
	mutex          sync.RWMutex
	requests       map[string][]time.Time
	blockedUntil   map[string]time.Time
	config         types.RateLimiterConfig
}

func NewMemoryRateLimiter(config types.Config) (*MemoryRateLimiter, error) {
	limiter := &MemoryRateLimiter{
		requests:       make(map[string][]time.Time),
		blockedUntil:   make(map[string]time.Time),
		config:         *config.RateLimiter,
	}

	go limiter.cleanupRoutine()

	return limiter, nil
}

// Allow checks if a request is allowed based on rate limiting rules
func (m *MemoryRateLimiter) Allow(key string, config types.LimiterConfig) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()

	// Check if the key is blocked
	if blockedTime, exists := m.blockedUntil[key]; exists && now.Before(blockedTime) {
		return false
	}

	// Get the requests for this key
	times, exists := m.requests[key]
	if !exists {
		// First request for this key
		m.requests[key] = []time.Time{now}
		return true
	}

	// Filter out requests outside the current window
	windowStart := now.Add(-config.WindowSize)
	var validTimes []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}

	// Check if the number of requests exceeds the limit
	if len(validTimes) >= config.MaxRequests {
		// Block this key for the specified duration
		m.blockedUntil[key] = now.Add(config.BlockDuration)
		return false
	}

	// Add the current request time and update the list
	validTimes = append(validTimes, now)
	m.requests[key] = validTimes

	return true
}

// Close implemented for the RateLimiter interface
func (m *MemoryRateLimiter) Close() error {
	// No resources to close for memory-based implementation
	return nil
}

// cleanupRoutine periodically cleans up expired entries to prevent memory leaks
func (m *MemoryRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

// cleanup removes expired entries from the maps
func (m *MemoryRateLimiter) cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()

	// Clean up blocked keys
	for key, blockedUntil := range m.blockedUntil {
		if now.After(blockedUntil) {
			delete(m.blockedUntil, key)
		}
	}

	// Clean up request times (keep entries with at least one valid time)
	for key, times := range m.requests {
		// Consider 24 hours as the maximum reasonable window size
		cutoff := now.Add(-24 * time.Hour)
		var validTimes []time.Time

		for _, t := range times {
			if t.After(cutoff) {
				validTimes = append(validTimes, t)
			}
		}

		if len(validTimes) == 0 {
			delete(m.requests, key)
		} else {
			m.requests[key] = validTimes
		}
	}

}
