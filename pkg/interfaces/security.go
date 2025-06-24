package interfaces

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

type CustomJWTClaimsProvider interface {
	GetClaims(user types.User) (map[string]interface{}, error)
}

type RateLimiter interface {
	Allow(key string, windowSize time.Duration, maxRequests int, blockDuration time.Duration) bool
	Close() error
}
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string, remoteIP string) (bool, error)
}
