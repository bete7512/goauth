package security

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestTokenDigestIsStableAndPrefixed(t *testing.T) {
	d := TokenDigest("abc")
	require.True(t, strings.HasPrefix(d, tokenDigestPrefix))
	require.Equal(t, d, TokenDigest("abc"))
	require.NotEqual(t, d, TokenDigest("abd"))
	require.NotContains(t, d, "abc")
}

func TestFindByTokenDigest(t *testing.T) {
	stored := map[string]string{
		TokenDigest("fresh"): "digest-row",
		"legacyrawvalue":     "legacy-row",
	}
	var lookups []string
	find := func(_ context.Context, value string) (string, error) {
		lookups = append(lookups, value)
		if row, ok := stored[value]; ok {
			return row, nil
		}
		return "", models.ErrNotFound
	}
	ctx := context.Background()

	row, err := FindByTokenDigest(ctx, "fresh", find)
	require.NoError(t, err)
	require.Equal(t, "digest-row", row)
	require.Equal(t, []string{TokenDigest("fresh")}, lookups, "a digest hit needs one lookup")

	lookups = nil
	row, err = FindByTokenDigest(ctx, "legacyrawvalue", find)
	require.NoError(t, err)
	require.Equal(t, "legacy-row", row, "rows written before digests stay redeemable")
	require.Len(t, lookups, 2)

	lookups = nil
	_, err = FindByTokenDigest(ctx, TokenDigest("fresh"), find)
	require.ErrorIs(t, err, models.ErrNotFound, "a digest copied from the database is not a token")
	require.Len(t, lookups, 1, "submissions shaped like a digest skip the legacy lookup")

	boom := errors.New("db down")
	_, err = FindByTokenDigest(ctx, "x", func(context.Context, string) (string, error) { return "", boom })
	require.ErrorIs(t, err, boom, "storage errors are returned, not retried as legacy lookups")
}

func TestCodeDigestAndMatches(t *testing.T) {
	key := CodeKey(types.SecurityConfig{JwtSecretKey: "a-secret-of-at-least-32-characters!"})
	stored := CodeDigest(key, "token-1", "123456")
	require.True(t, strings.HasPrefix(stored, codeDigestPrefix))
	require.NotContains(t, stored, "123456")

	require.True(t, CodeMatches(key, "token-1", stored, "123456"))
	require.False(t, CodeMatches(key, "token-1", stored, "000000"), "wrong code")
	require.False(t, CodeMatches(key, "token-2", stored, "123456"), "digest is bound to its row")
	require.False(t, CodeMatches(key, "token-1", stored, stored), "the stored digest is not a code")

	other := CodeKey(types.SecurityConfig{JwtSecretKey: "another-secret-of-at-least-32-chars"})
	require.False(t, CodeMatches(other, "token-1", stored, "123456"), "digest depends on the server secret")

	require.True(t, CodeMatches(key, "token-1", "654321", "654321"), "legacy plain codes still compare")
	require.False(t, CodeMatches(key, "token-1", "654321", "000000"))
	require.False(t, CodeMatches(key, "token-1", "", ""), "empty values never match")
}
