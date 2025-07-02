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
	Allow(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool
	AllowN(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration, n int) bool
	Close() error
}
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string, remoteIP string) (bool, error)
}
