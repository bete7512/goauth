package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

// maxTypedClaimsBytes bounds the claims of a typed token, like signJWT does.
const maxTypedClaimsBytes = 4096

// TokenSigner signs and verifies JWTs that are not first-party session
// credentials, such as OAuth access tokens issued to third-party clients.
// Every token carries an explicit JOSE "typ" header and Verify requires it,
// so a token of one type is never accepted as another. Verify applies none of
// the first-party issuer and audience rules: callers check those claims.
//
// Only asymmetric keys are accepted, because the tokens are verified by other
// parties from the public key set.
type TokenSigner struct {
	keyring  *jwtKeyring
	retained map[string]retainedJWTKey
}

// NewTokenSigner builds a signer from the JWT key fields of cfg
// (JWTAlgorithm, JWTPrivateKeyPEM or JWTPrivateKeyFile, the optional public
// key, JWTKeyID and RetainedJWTKeys). An empty JWTAlgorithm is inferred from
// the private key.
func NewTokenSigner(cfg types.SecurityConfig) (*TokenSigner, error) {
	if cfg.JWTAlgorithm == "" {
		alg, err := inferJWTAlgorithm(cfg)
		if err != nil {
			return nil, err
		}
		cfg.JWTAlgorithm = alg
	}
	if !cfg.JWTAlgorithm.IsAsymmetric() {
		return nil, fmt.Errorf("token signer requires RS256 or ES256, got %s", cfg.JWTAlgorithm)
	}
	keyring, err := newJWTKeyring(cfg)
	if err != nil {
		return nil, err
	}
	for _, key := range cfg.RetainedJWTKeys {
		if !key.Algorithm.IsAsymmetric() {
			return nil, errors.New("retained token signer keys must be RS256 or ES256")
		}
	}
	retained, err := loadRetainedKeys(keyring, cfg.RetainedJWTKeys)
	if err != nil {
		return nil, err
	}
	return &TokenSigner{keyring: keyring, retained: retained}, nil
}

// inferJWTAlgorithm picks RS256 or ES256 from the configured private key.
func inferJWTAlgorithm(cfg types.SecurityConfig) (types.JWTAlgorithm, error) {
	if _, err := loadRSAPrivateKey(cfg); err == nil {
		return types.JWTAlgorithmRS256, nil
	}
	if _, err := loadECPrivateKey(cfg); err == nil {
		return types.JWTAlgorithmES256, nil
	}
	return "", errors.New("signing key must be a PEM-encoded RSA or P-256 EC private key")
}

// TokenSigner returns a signer that shares the manager's active and retained
// keys. It fails when the manager signs with HS256.
func (t *SecurityManager) TokenSigner() (*TokenSigner, error) {
	if t.keyring == nil {
		return nil, errors.New("security manager: keyring not initialized")
	}
	if !t.keyring.algorithm.IsAsymmetric() {
		return nil, fmt.Errorf("JWT algorithm %s is symmetric", t.keyring.algorithm)
	}
	retained := make(map[string]retainedJWTKey, len(t.retained))
	for id, key := range t.retained {
		if key.key.algorithm.IsAsymmetric() {
			retained[id] = key
		}
	}
	return &TokenSigner{keyring: t.keyring, retained: retained}, nil
}

// Sign signs claims with the active key and sets the JOSE "typ" header.
func (s *TokenSigner) Sign(typ string, claims map[string]interface{}) (string, error) {
	if typ == "" || strings.EqualFold(typ, "JWT") {
		return "", errors.New("typed token requires an explicit type other than JWT")
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxTypedClaimsBytes {
		return "", fmt.Errorf("JWT claims exceed %d bytes", maxTypedClaimsBytes)
	}
	token := jwt.NewWithClaims(s.keyring.method, jwt.MapClaims(claims))
	token.Header["typ"] = typ
	s.keyring.applyHeader(token)
	return token.SignedString(s.keyring.signKey())
}

// Verify checks the signature against the active or a retained key, requires
// the JOSE "typ" header to equal typ and requires an unexpired "exp". It does
// not check "iss" or "aud".
func (s *TokenSigner) Verify(typ string, tokenString string) (map[string]interface{}, error) {
	allowed := []string{s.keyring.method.Alg()}
	for _, key := range s.retained {
		allowed = append(allowed, key.key.method.Alg())
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if header, _ := token.Header["typ"].(string); header != typ {
			return nil, errors.New("unexpected token type")
		}
		kid, _ := token.Header["kid"].(string)
		key := s.keyring
		if kid != key.kid {
			retained, ok := s.retained[kid]
			if !ok || !time.Now().Before(retained.notAfter) {
				return nil, errors.New("unknown or retired JWT key")
			}
			key = retained.key
		}
		if token.Method.Alg() != key.method.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return key.verifyKey(), nil
	}, jwt.WithValidMethods(allowed), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return map[string]interface{}(claims), nil
}

// JWKS returns the public keys that verify this signer's tokens: the active
// key and retained keys that have not retired.
func (s *TokenSigner) JWKS() types.JWKS {
	keys := s.keyring.jwks()
	for _, key := range s.retained {
		if time.Now().Before(key.notAfter) {
			keys.Keys = append(keys.Keys, key.key.jwks().Keys...)
		}
	}
	return keys
}

// Algorithm reports the active signing algorithm.
func (s *TokenSigner) Algorithm() types.JWTAlgorithm {
	return s.keyring.algorithm
}

// KeyID reports the active key ID.
func (s *TokenSigner) KeyID() string {
	return s.keyring.kid
}
