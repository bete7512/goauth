package security

import (
	"crypto/elliptic"
	"fmt"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type retainedJWTKey struct {
	key      *jwtKeyring
	notAfter time.Time
}

func loadRetainedKeys(active *jwtKeyring, keys []types.JWTVerificationKey) (map[string]retainedJWTKey, error) {
	retained := make(map[string]retainedJWTKey, len(keys))
	for _, cfg := range keys {
		if cfg.ID == "" || cfg.ID == active.kid {
			return nil, fmt.Errorf("retained JWT key ID must be nonempty and distinct")
		}
		if _, exists := retained[cfg.ID]; exists {
			return nil, fmt.Errorf("duplicate retained JWT key ID")
		}
		if cfg.NotAfter.IsZero() {
			return nil, fmt.Errorf("retained JWT key requires a retirement time")
		}
		key := &jwtKeyring{kid: cfg.ID, algorithm: cfg.Algorithm}
		var err error
		switch cfg.Algorithm {
		case types.JWTAlgorithmHS256:
			if len(cfg.Secret) < 32 {
				return nil, fmt.Errorf("retained HMAC key must be at least 32 bytes")
			}
			key.method = jwt.SigningMethodHS256
			key.secret = []byte(cfg.Secret)
		case types.JWTAlgorithmRS256:
			if len(cfg.PublicKeyPEM) == 0 {
				return nil, fmt.Errorf("retained RSA public key is required")
			}
			key.method = jwt.SigningMethodRS256
			key.publicKey, err = loadRSAPublicKey(types.SecurityConfig{JWTPublicKeyPEM: cfg.PublicKeyPEM}, nil)
		case types.JWTAlgorithmES256:
			if len(cfg.PublicKeyPEM) == 0 {
				return nil, fmt.Errorf("retained EC public key is required")
			}
			key.method = jwt.SigningMethodES256
			pub, loadErr := loadECPublicKey(types.SecurityConfig{JWTPublicKeyPEM: cfg.PublicKeyPEM}, nil)
			err = loadErr
			if err == nil && pub.Curve != elliptic.P256() {
				return nil, fmt.Errorf("ES256 requires P-256")
			}
			key.publicKey = pub
		default:
			return nil, fmt.Errorf("unsupported retained key algorithm")
		}
		if err != nil {
			return nil, err
		}
		retained[cfg.ID] = retainedJWTKey{key: key, notAfter: cfg.NotAfter}
	}
	return retained, nil
}
