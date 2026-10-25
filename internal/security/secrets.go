package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Single-use secrets (email verification, password reset, magic-link and
// invitation tokens, and the short codes sent by SMS or email) are stored as
// digests, so reading the database or a backup does not yield credentials
// that can be redeemed. The raw value exists only in the delivered link or
// message.
const (
	// tokenDigestPrefix marks a stored SHA-256 digest of a high-entropy token.
	// Raw tokens are hex and never contain ':', which keeps the legacy lookup
	// in FindByTokenDigest from accepting a stored digest as a token.
	tokenDigestPrefix = "s1:"
	// codeDigestPrefix marks a stored HMAC of a short code.
	codeDigestPrefix = "h1:"
	codeKeyLabel     = "goauth/short-code/v1"
)

// TokenDigest returns the stored form of a high-entropy bearer token.
func TokenDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return tokenDigestPrefix + hex.EncodeToString(sum[:])
}

// FindByTokenDigest looks a submitted token up by its digest. Rows written
// before digests were introduced hold the raw value, so a miss falls back to
// a raw lookup, except for submissions that look like a stored digest: those
// could otherwise match a digest copied out of the database.
func FindByTokenDigest[T any](ctx context.Context, raw string, find func(context.Context, string) (T, error)) (T, error) {
	record, err := find(ctx, TokenDigest(raw))
	if err == nil || !errors.Is(err, models.ErrNotFound) || raw == "" || strings.HasPrefix(raw, tokenDigestPrefix) {
		return record, err
	}
	return find(ctx, raw)
}

// CodeKey derives the key for short-code digests from the JWT secret, which
// configuration validation requires for every signing algorithm. Rotating
// that secret invalidates codes still in flight; they live an hour at most.
func CodeKey(cfg types.SecurityConfig) []byte {
	mac := hmac.New(sha256.New, []byte(cfg.JwtSecretKey))
	mac.Write([]byte(codeKeyLabel))
	return mac.Sum(nil)
}

// CodeDigest returns the stored form of a short code, bound to the token row
// it belongs to. A keyed digest matters here: an unkeyed hash of a six-digit
// code is reversed by trying a million values.
func CodeDigest(key []byte, tokenID, code string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tokenID))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return codeDigestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// CodeMatches compares a submitted code with the stored value in constant
// time. Rows written before digests were introduced hold the plain code.
func CodeMatches(key []byte, tokenID, stored, submitted string) bool {
	if stored == "" || submitted == "" {
		return false
	}
	expected := submitted
	if strings.HasPrefix(stored, codeDigestPrefix) {
		expected = CodeDigest(key, tokenID, submitted)
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(expected)) == 1
}
