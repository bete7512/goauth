package services

import (
	"fmt"
	"sync"
	"time"
)

// RateLimiterService manages rate limiting using token bucket algorithm
type RateLimiterService struct {
	requestsPerMinute int
	requestsPerHour   int
	burstSize         int
	refillRate        float64 // Tokens per second
	clients           map[string]*ClientLimiter
	mu                sync.RWMutex
	tierName          string // For observability
}

// ClientLimiter tracks rate limits for a specific client using token bucket
type ClientLimiter struct {
	// Token bucket for burst control
	tokens          float64
	lastRefillTime  time.Time
	maxTokens       float64
	refillRate      float64

	// Sliding window counters for per-minute and per-hour limits
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
	mu          sync.Mutex
}

// RateLimitResult contains information about rate limit check
type RateLimitResult struct {
	Allowed     bool
	RetryAfter  int    // Seconds until next request allowed
	Limit       string // Human-readable limit description
	Remaining   int    // Tokens/requests remaining
}

func NewRateLimiterService(requestsPerMinute, requestsPerHour, burstSize int) *RateLimiterService {
	return NewRateLimiterServiceWithTier("default", requestsPerMinute, requestsPerHour, burstSize)
}

func NewRateLimiterServiceWithTier(tierName string, requestsPerMinute, requestsPerHour, burstSize int) *RateLimiterService {
	// Calculate refill rate: tokens per second based on requests per minute
	refillRate := float64(requestsPerMinute) / 60.0

	service := &RateLimiterService{
		requestsPerMinute: requestsPerMinute,
		requestsPerHour:   requestsPerHour,
		burstSize:         burstSize,
		refillRate:        refillRate,
		clients:           make(map[string]*ClientLimiter),
		tierName:          tierName,
	}

	// Start cleanup goroutine
	go service.cleanup()

	return service
}

// Allow checks if a request is allowed for the given client identifier
func (s *RateLimiterService) Allow(identifier string) bool {
	result := s.Check(identifier)
	return result.Allowed
}

// Check performs a detailed rate limit check with retry information
func (s *RateLimiterService) Check(identifier string) *RateLimitResult {
	s.mu.Lock()
	limiter, exists := s.clients[identifier]
	if !exists {
		now := time.Now()
		limiter = &ClientLimiter{
			tokens:         float64(s.burstSize),
			lastRefillTime: now,
			maxTokens:      float64(s.burstSize),
			refillRate:     s.refillRate,
			minuteReset:    now.Add(time.Minute),
			hourReset:      now.Add(time.Hour),
		}
		s.clients[identifier] = limiter
	}
	s.mu.Unlock()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()

	// Refill tokens based on time elapsed
	elapsed := now.Sub(limiter.lastRefillTime).Seconds()
	tokensToAdd := elapsed * limiter.refillRate
	limiter.tokens = min(limiter.tokens+tokensToAdd, limiter.maxTokens)
	limiter.lastRefillTime = now

	// Reset sliding window counters if needed
	if now.After(limiter.minuteReset) {
		limiter.minuteCount = 0
		limiter.minuteReset = now.Add(time.Minute)
	}
	if now.After(limiter.hourReset) {
		limiter.hourCount = 0
		limiter.hourReset = now.Add(time.Hour)
	}

	// Check all limits
	result := &RateLimitResult{
		Allowed:   true,
		Limit:     s.formatLimits(),
		Remaining: int(limiter.tokens),
	}

	// Token bucket check (burst protection)
	if limiter.tokens < 1 {
		result.Allowed = false
		result.RetryAfter = int((1.0 - limiter.tokens) / limiter.refillRate)
		result.Remaining = 0
		return result
	}

	// Per-minute check
	if limiter.minuteCount >= s.requestsPerMinute {
		result.Allowed = false
		result.RetryAfter = int(time.Until(limiter.minuteReset).Seconds())
		result.Remaining = 0
		return result
	}

	// Per-hour check
	if limiter.hourCount >= s.requestsPerHour {
		result.Allowed = false
		result.RetryAfter = int(time.Until(limiter.hourReset).Seconds())
		result.Remaining = 0
		return result
	}

	// All checks passed - consume one token and increment counters
	limiter.tokens -= 1
	limiter.minuteCount++
	limiter.hourCount++

	result.Remaining = s.requestsPerMinute - limiter.minuteCount

	return result
}

// formatLimits returns a human-readable limit description
func (s *RateLimiterService) formatLimits() string {
	if s.requestsPerMinute > 0 && s.requestsPerHour > 0 {
		return fmt.Sprintf("%d/min, %d/hour", s.requestsPerMinute, s.requestsPerHour)
	} else if s.requestsPerMinute > 0 {
		return fmt.Sprintf("%d/min", s.requestsPerMinute)
	} else if s.requestsPerHour > 0 {
		return fmt.Sprintf("%d/hour", s.requestsPerHour)
	}
	return "unlimited"
}

// cleanup removes expired limiters to prevent memory leaks
func (s *RateLimiterService) cleanup() {
	ticker := time.NewTicker(5 * time.Minute) // More frequent cleanup
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, limiter := range s.clients {
			limiter.mu.Lock()
			// Remove if inactive for more than 1 hour
			if now.Sub(limiter.lastRefillTime) > time.Hour {
				delete(s.clients, id)
			}
			limiter.mu.Unlock()
		}
		s.mu.Unlock()
	}
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
