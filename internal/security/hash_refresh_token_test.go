package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashRefreshToken_Deterministic(t *testing.T) {
	token := "some-high-entropy-refresh-token-abc123"
	h1 := HashRefreshToken(token)
	h2 := HashRefreshToken(token)
	assert.Equal(t, h1, h2, "same input should produce same hash")
}

func TestHashRefreshToken_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := HashRefreshToken("token-a")
	h2 := HashRefreshToken("token-b")
	assert.NotEqual(t, h1, h2)
}

func TestHashRefreshToken_NotPlaintext(t *testing.T) {
	token := "my-secret-refresh-token"
	hash := HashRefreshToken(token)
	assert.NotEqual(t, token, hash, "hash must not equal the original token")
	assert.Len(t, hash, 64, "SHA-256 hex output is 64 characters")
}
