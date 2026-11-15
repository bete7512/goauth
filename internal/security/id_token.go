package security

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// idTokenType is the JOSE "typ" of an OpenID Connect ID token. Relying-party
// libraries commonly accept only "JWT" or no type at all, so an ID token
// cannot carry a type of its own the way an OAuth access token does.
const idTokenType = "JWT"

// SignIDToken signs an OpenID Connect ID token with the active key.
//
// An ID token has the same JOSE type as GoAuth's own access tokens, so the
// type cannot tell the two apart. A signer used for ID tokens must therefore
// hold a key of its own: build it with NewTokenSigner from a dedicated key
// and check it with SharesKeyWith against the security manager's signer.
func (s *TokenSigner) SignIDToken(claims map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxTypedClaimsBytes {
		return "", fmt.Errorf("ID token claims exceed %d bytes", maxTypedClaimsBytes)
	}
	token := jwt.NewWithClaims(s.keyring.method, jwt.MapClaims(claims))
	token.Header["typ"] = idTokenType
	s.keyring.applyHeader(token)
	return token.SignedString(s.keyring.signKey())
}

// SharesKeyWith reports whether the active key of s is one of the keys of
// other, active or retained. Tokens signed by s would then verify against
// other's key set.
func (s *TokenSigner) SharesKeyWith(other *TokenSigner) bool {
	if other == nil {
		return false
	}
	mine, ok := s.keyring.publicKey.(interface {
		Equal(x crypto.PublicKey) bool
	})
	if !ok {
		return false
	}
	if mine.Equal(other.keyring.publicKey) {
		return true
	}
	for _, retained := range other.retained {
		if retained.key != nil && mine.Equal(retained.key.publicKey) {
			return true
		}
	}
	return false
}
