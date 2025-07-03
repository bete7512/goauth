package ratelimiter

import (
	"context"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"golang.org/x/time/rate"
)

type LimiterEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
	blocked  time.Time
}

type MemoryRateLimiter struct {
	mutex    sync.RWMutex
	limiters map[string]*LimiterEntry
	config   config.RateLimiterConfig
}

func NewMemoryRateLimiter(conf config.Config) (*MemoryRateLimiter, error) {
	limiter := &MemoryRateLimiter{
		limiters: make(map[string]*LimiterEntry),
		config:   conf.Security.RateLimiter,
	}

	go limiter.cleanupRoutine()

	return limiter, nil
}

// Allow checks if a request is allowed based on rate limiting rules
func (m *MemoryRateLimiter) Allow(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool {
	return m.AllowN(key, windowSize, maxRequests, blockDuration, 1)
}

// AllowN checks if N requests are allowed
func (m *MemoryRateLimiter) AllowN(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration, n int) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()

	// Get or create limiter entry
	entry, exists := m.limiters[key]
	if !exists {
		// Create a new rate limiter
		rps := rate.Limit(float64(maxRequests) / windowSize.Seconds())
		entry = &LimiterEntry{
			limiter:  rate.NewLimiter(rps, maxRequests),
			lastUsed: now,
		}
		m.limiters[key] = entry
	}

	// Check if the key is blocked
	if !entry.blocked.IsZero() && now.Before(entry.blocked) {
		return false
	}

	// Update last used time
	entry.lastUsed = now

	// Check if request is allowed
	if !entry.limiter.AllowN(now, n) {
		// Block this key for the specified duration
		entry.blocked = now.Add(blockDuration)
		return false
	}

	// Clear blocked status if it was set
	entry.blocked = time.Time{}

	return true
}

// Reserve reserves tokens for future use
func (m *MemoryRateLimiter) Reserve(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) *rate.Reservation {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()

	// Get or create limiter entry
	entry, exists := m.limiters[key]
	if !exists {
		rps := rate.Limit(float64(maxRequests) / windowSize.Seconds())
		entry = &LimiterEntry{
			limiter:  rate.NewLimiter(rps, maxRequests),
			lastUsed: now,
		}
		m.limiters[key] = entry
	}

	entry.lastUsed = now
	return entry.limiter.Reserve()
}

// Wait waits until the request can be processed
func (m *MemoryRateLimiter) Wait(ctx context.Context, key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) error {
	m.mutex.Lock()

	now := time.Now()

	// Get or create limiter entry
	entry, exists := m.limiters[key]
	if !exists {
		rps := rate.Limit(float64(maxRequests) / windowSize.Seconds())
		entry = &LimiterEntry{
			limiter:  rate.NewLimiter(rps, maxRequests),
			lastUsed: now,
		}
		m.limiters[key] = entry
	}

	// Check if blocked
	if !entry.blocked.IsZero() && now.Before(entry.blocked) {
		m.mutex.Unlock()
		// Wait for block to expire
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Until(entry.blocked)):
			// Block expired, continue
		}
		m.mutex.Lock()
	}

	entry.lastUsed = now
	limiter := entry.limiter
	m.mutex.Unlock()

	return limiter.Wait(ctx)
}

// GetLimiterStats returns statistics for a given key
func (m *MemoryRateLimiter) GetLimiterStats(key string) (tokens float64, isBlocked bool, blockedUntil time.Time) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if entry, exists := m.limiters[key]; exists {
		tokens = entry.limiter.Tokens()
		isBlocked = !entry.blocked.IsZero() && time.Now().Before(entry.blocked)
		blockedUntil = entry.blocked
	}

	return
}

// Close implemented for the RateLimiter interface
func (m *MemoryRateLimiter) Close() error {
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
	cutoff := now.Add(-1 * time.Hour) // Remove entries unused for 1 hour

	for key, entry := range m.limiters {
		// Remove if:
		// 1. Not blocked and hasn't been used recently and bucket is full
		// 2. Or blocked but block has expired and hasn't been used recently
		shouldRemove := false

		if entry.blocked.IsZero() {
			// Not blocked - remove if unused and bucket is full
			if entry.lastUsed.Before(cutoff) && entry.limiter.Tokens() == float64(entry.limiter.Burst()) {
				shouldRemove = true
			}
		} else if now.After(entry.blocked) {
			// Block has expired - remove if unused recently
			if entry.lastUsed.Before(cutoff) {
				shouldRemove = true
			}
		}

		if shouldRemove {
			delete(m.limiters, key)
		}
	}
}

// SetLimiterParams updates the rate limiter parameters for a specific key
func (m *MemoryRateLimiter) SetLimiterParams(key string, windowSize time.Duration, maxRequests int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	rps := rate.Limit(float64(maxRequests) / windowSize.Seconds())

	if entry, exists := m.limiters[key]; exists {
		entry.limiter.SetLimit(rps)
		entry.limiter.SetBurst(maxRequests)
	} else {
		m.limiters[key] = &LimiterEntry{
			limiter:  rate.NewLimiter(rps, maxRequests),
			lastUsed: time.Now(),
		}
	}
}
