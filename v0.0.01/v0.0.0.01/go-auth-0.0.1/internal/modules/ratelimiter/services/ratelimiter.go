package services

import (
	"sync"
	"time"
)

// RateLimiterService manages rate limiting
type RateLimiterService struct {
	requestsPerMinute int
	requestsPerHour   int
	burstSize         int
	clients           map[string]*ClientLimiter
	mu                sync.RWMutex
}

// ClientLimiter tracks rate limits for a specific client
type ClientLimiter struct {
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
	mu          sync.Mutex
}

func NewRateLimiterService(requestsPerMinute, requestsPerHour, burstSize int) *RateLimiterService {
	service := &RateLimiterService{
		requestsPerMinute: requestsPerMinute,
		requestsPerHour:   requestsPerHour,
		burstSize:         burstSize,
		clients:           make(map[string]*ClientLimiter),
	}

	// Start cleanup goroutine
	go service.cleanup()

	return service
}

// Allow checks if a request is allowed for the given client IP
func (s *RateLimiterService) Allow(clientIP string) bool {
	s.mu.Lock()
	limiter, exists := s.clients[clientIP]
	if !exists {
		limiter = &ClientLimiter{
			minuteReset: time.Now().Add(time.Minute),
			hourReset:   time.Now().Add(time.Hour),
		}
		s.clients[clientIP] = limiter
	}
	s.mu.Unlock()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := time.Now()

	// Reset counters if needed
	if now.After(limiter.minuteReset) {
		limiter.minuteCount = 0
		limiter.minuteReset = now.Add(time.Minute)
	}
	if now.After(limiter.hourReset) {
		limiter.hourCount = 0
		limiter.hourReset = now.Add(time.Hour)
	}

	// Check limits
	if limiter.minuteCount >= s.requestsPerMinute || limiter.hourCount >= s.requestsPerHour {
		return false
	}

	limiter.minuteCount++
	limiter.hourCount++
	return true
}

// cleanup removes expired limiters
func (s *RateLimiterService) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for ip, limiter := range s.clients {
			limiter.mu.Lock()
			if now.After(limiter.hourReset) {
				delete(s.clients, ip)
			}
			limiter.mu.Unlock()
		}
		s.mu.Unlock()
	}
}
