package types

//go:generate mockgen -destination=../../internal/mocks/mock_ratelimit_store.go -package=mocks github.com/bete7512/goauth/pkg/types RateLimitStore

import (
	"context"
	"time"
)

// RateLimitKey selects what a rate-limit rule counts.
type RateLimitKey string

const (
	// RateLimitKeyIP counts requests per client IP. Forwarded headers are
	// honored only behind a configured trusted proxy.
	RateLimitKeyIP RateLimitKey = "ip"
	// RateLimitKeyIdentifier counts requests per submitted identifier (the
	// email, username or phone number in a JSON request body).
	RateLimitKeyIdentifier RateLimitKey = "identifier"
	// RateLimitKeyIPIdentifier counts requests per (client IP, identifier) pair.
	RateLimitKeyIPIdentifier RateLimitKey = "ip_identifier"
)

// RateLimitRule is a token-bucket budget: Limit requests per Window, with at
// most Burst requests accepted back to back. A zero Burst means Limit.
type RateLimitRule struct {
	Limit  int
	Window time.Duration
	Burst  int
}

// RateLimitDecision is the outcome of charging one request against a rule.
type RateLimitDecision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Limit is the burst capacity advertised to the client.
	Limit int
	// Remaining is the number of requests still available right now.
	Remaining int
	// RetryAfter is how long the client must wait; zero when Allowed.
	RetryAfter time.Duration
	// ResetAt is when the budget is fully replenished.
	ResetAt time.Time
}

// RateLimitStore records request arrivals per key. Take must be atomic per
// key: concurrent callers for the same key observe one consistent budget.
// Keys are opaque prefixed strings; implementations must not interpret them.
// Implementations for shared stores (for example Redis) make the limiter
// correct across replicas; the built-in memory store is per process.
type RateLimitStore interface {
	// Take charges one request to key under rule at time now.
	Take(ctx context.Context, key string, rule RateLimitRule, now time.Time) (RateLimitDecision, error)
	// Reset forgets the budget state for key.
	Reset(ctx context.Context, key string) error
	// Close releases store resources.
	Close() error
}
