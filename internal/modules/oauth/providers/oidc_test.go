package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCVerificationProfile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "trusted", Algorithm: "RS256", Use: "sig"}}})
	require.NoError(t, err)
	for _, test := range []struct {
		name   string
		mutate func(jwt.MapClaims)
		key    *rsa.PrivateKey
		status int
		valid  bool
	}{
		{name: "valid", valid: true},
		{name: "wrong signature", key: other},
		{name: "wrong issuer", mutate: func(c jwt.MapClaims) { c["iss"] = "https://attacker.example" }},
		{name: "wrong audience", mutate: func(c jwt.MapClaims) { c["aud"] = "another-client" }},
		{name: "expired", mutate: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{name: "missing subject", mutate: func(c jwt.MapClaims) { delete(c, "sub") }},
		{name: "missing expiry", mutate: func(c jwt.MapClaims) { delete(c, "exp") }},
		{name: "verification outage", status: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := NewBaseProvider("test", "client", "secret", "", "", "", nil)
			p.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, "https://issuer.example/keys", r.URL.String())
				status := test.status
				if status == 0 {
					status = 200
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(jwks)))}, nil
			})}
			claims := jwt.MapClaims{"iss": "https://issuer.example", "sub": "subject", "aud": "client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
			if test.mutate != nil {
				test.mutate(claims)
			}
			signing := key
			if test.key != nil {
				signing = test.key
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "trusted"
			raw, err := token.SignedString(signing)
			require.NoError(t, err)
			var verifier oidcVerifier
			_, err = verifier.verify(context.Background(), p, "https://issuer.example", "https://issuer.example/keys", raw)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
