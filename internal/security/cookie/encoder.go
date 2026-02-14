package cookie

//go:generate mockgen -destination=../../../internal/mocks/mock_cookie_encoder.go -package=mocks github.com/bete7512/goauth/internal/security/cookie CookieEncoder

import (
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/types"
)

var (
	ErrInvalidFormat = errors.New("invalid session cookie format")
	ErrInvalidHMAC   = errors.New("session cookie signature verification failed")
	ErrExpired       = errors.New("session cookie expired")
)

// CookieEncoder encodes and decodes session data for cookie-cached sessions.
// Implementations must be safe for concurrent use.
type CookieEncoder interface {
	// Encode signs and serializes session data into a cookie value.
	Encode(data *types.SessionCookieData) (string, error)

	// Decode verifies signature, checks expiry, and returns session data.
	// Returns ErrInvalidFormat, ErrInvalidHMAC, or ErrExpired on failure.
	Decode(cookieValue string) (*types.SessionCookieData, error)

	// MaxSize returns the approximate maximum cookie value size in bytes.
	MaxSize() int

	// EncodingType returns which encoding this encoder uses.
	EncodingType() types.CookieEncoding
}

// NewEncoder creates a CookieEncoder for the given encoding type.
// key is the HMAC/JWT signing key.
// Panics on unknown encoding type (fail-fast on misconfiguration).
func NewEncoder(encoding types.CookieEncoding, key string) CookieEncoder {
	switch encoding {
	case types.CookieEncodingCompact, "":
		return newCompactEncoder(key)
	case types.CookieEncodingJWT:
		return newJWTEncoder(key)
	default:
		panic(fmt.Sprintf("goauth: unknown cookie encoding: %q", encoding))
	}
}
