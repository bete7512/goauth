package interfaces

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

type CustomJWTClaimsProvider interface {
	GetClaims(user models.User) (map[string]interface{}, error)
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool
	AllowN(ctx context.Context, key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration, n int) bool
	GetStats(ctx context.Context, key string, windowSize time.Duration) (currentRequests int64, isBlocked bool, blockedUntil time.Time)
	Reset(ctx context.Context, key string) error
	Close() error
}

type CaptchaVerifier interface {
	Verify(ctx context.Context, token string, remoteIP string) (bool, error)
}

type CSRFManager interface {
	GenerateToken(ctx context.Context, userID string) (string, error)
	ValidateToken(ctx context.Context, token string, userID string) (bool, error)
	RevokeToken(ctx context.Context, token string) error
	Close() error
}
