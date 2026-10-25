package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

// jwtKeyring holds the parsed signing material for the configured JWT algorithm.
// For HS256 only the secret is used. For RS256/ES256, privateKey signs and
// publicKey is served at the JWKS endpoint.
type jwtKeyring struct {
	algorithm  types.JWTAlgorithm
	method     jwt.SigningMethod
	secret     []byte // HS256
	privateKey any    // *rsa.PrivateKey or *ecdsa.PrivateKey
	publicKey  any    // *rsa.PublicKey or *ecdsa.PublicKey
	kid        string
}

func newJWTKeyring(cfg types.SecurityConfig) (*jwtKeyring, error) {
	alg := cfg.JWTAlgorithm
	if alg == "" {
		alg = types.JWTAlgorithmHS256
	}

	switch alg {
	case types.JWTAlgorithmHS256:
		return &jwtKeyring{
			algorithm: alg,
			method:    jwt.SigningMethodHS256,
			secret:    []byte(cfg.JwtSecretKey),
			kid:       cfg.JWTKeyID, // may be empty — HS256 doesn't expose a JWKS entry
		}, nil

	case types.JWTAlgorithmRS256:
		priv, err := loadRSAPrivateKey(cfg)
		if err != nil {
			return nil, err
		}
		pub, err := loadRSAPublicKey(cfg, priv)
		if err != nil {
			return nil, err
		}
		if !priv.PublicKey.Equal(pub) {
			return nil, errors.New("RSA signing and verification keys do not match")
		}
		if priv.N.BitLen() < 2048 {
			return nil, errors.New("RSA keys must be at least 2048 bits")
		}
		kid := cfg.JWTKeyID
		if kid == "" {
			kid = rsaKID(pub)
		}
		return &jwtKeyring{
			algorithm:  alg,
			method:     jwt.SigningMethodRS256,
			privateKey: priv,
			publicKey:  pub,
			kid:        kid,
		}, nil

	case types.JWTAlgorithmES256:
		priv, err := loadECPrivateKey(cfg)
		if err != nil {
			return nil, err
		}
		pub, err := loadECPublicKey(cfg, priv)
		if err != nil {
			return nil, err
		}
		if !priv.PublicKey.Equal(pub) {
			return nil, errors.New("EC signing and verification keys do not match")
		}
		if priv.Curve != elliptic.P256() {
			return nil, errors.New("ES256 requires a P-256 key")
		}
		kid := cfg.JWTKeyID
		if kid == "" {
			kid = ecKID(pub)
		}
		return &jwtKeyring{
			algorithm:  alg,
			method:     jwt.SigningMethodES256,
			privateKey: priv,
			publicKey:  pub,
			kid:        kid,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported JWT algorithm: %s", alg)
	}
}

// signKey returns the key passed to jwt.Token.SignedString.
func (k *jwtKeyring) signKey() any {
	switch k.algorithm {
	case types.JWTAlgorithmHS256:
		return k.secret
	default:
		return k.privateKey
	}
}

// verifyKey returns the key used by jwt.Parse's keyfunc.
func (k *jwtKeyring) verifyKey() any {
	switch k.algorithm {
	case types.JWTAlgorithmHS256:
		return k.secret
	default:
		return k.publicKey
	}
}

// applyHeader sets the algorithm-specific JWT header fields.
// "kid" is included whenever a non-empty key ID is configured — downstream
// consumers rely on it to select the right JWKS entry during rotation.
func (k *jwtKeyring) applyHeader(t *jwt.Token) {
	if k.kid != "" {
		t.Header["kid"] = k.kid
	}
}

// JWKS returns the public key set. HS256 returns an empty set since the
// symmetric secret must not be exposed.
func (k *jwtKeyring) jwks() types.JWKS {
	switch k.algorithm {
	case types.JWTAlgorithmRS256:
		pub, _ := k.publicKey.(*rsa.PublicKey)
		if pub == nil {
			return types.JWKS{Keys: []types.JWK{}}
		}
		return types.JWKS{Keys: []types.JWK{{
			Kty: "RSA",
			Use: "sig",
			Alg: string(k.algorithm),
			Kid: k.kid,
			N:   base64urlBigInt(pub.N),
			E:   base64urlInt(pub.E),
		}}}
	case types.JWTAlgorithmES256:
		pub, _ := k.publicKey.(*ecdsa.PublicKey)
		x, y, ok := ecCoordinates(pub)
		if !ok {
			return types.JWKS{Keys: []types.JWK{}}
		}
		return types.JWKS{Keys: []types.JWK{{
			Kty: "EC",
			Use: "sig",
			Alg: string(k.algorithm),
			Kid: k.kid,
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
		}}}
	default:
		return types.JWKS{Keys: []types.JWK{}}
	}
}

// --- key loading ---

func readKeyMaterial(inline []byte, path string, label string) ([]byte, error) {
	if len(inline) > 0 {
		return inline, nil
	}
	if path == "" {
		return nil, fmt.Errorf("%s is required for the configured JWT algorithm", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	return data, nil
}

func parsePEMBlock(data []byte, label string) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", label)
	}
	return block, nil
}

func loadRSAPrivateKey(cfg types.SecurityConfig) (*rsa.PrivateKey, error) {
	data, err := readKeyMaterial(cfg.JWTPrivateKeyPEM, cfg.JWTPrivateKeyFile, "JWTPrivateKey")
	if err != nil {
		return nil, err
	}
	block, err := parsePEMBlock(data, "JWTPrivateKey")
	if err != nil {
		return nil, err
	}

	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
		return rsaKey, nil
	}
	return nil, errors.New("failed to parse RSA private key: expected PKCS1 or PKCS8 PEM")
}

func loadRSAPublicKey(cfg types.SecurityConfig, priv *rsa.PrivateKey) (*rsa.PublicKey, error) {
	if len(cfg.JWTPublicKeyPEM) == 0 && cfg.JWTPublicKeyFile == "" {
		return &priv.PublicKey, nil
	}
	data, err := readKeyMaterial(cfg.JWTPublicKeyPEM, cfg.JWTPublicKeyFile, "JWTPublicKey")
	if err != nil {
		return nil, err
	}
	block, err := parsePEMBlock(data, "JWTPublicKey")
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try PKCS1 public key format
		if rsaPub, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes); pkcs1Err == nil {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}

func loadECPrivateKey(cfg types.SecurityConfig) (*ecdsa.PrivateKey, error) {
	data, err := readKeyMaterial(cfg.JWTPrivateKeyPEM, cfg.JWTPrivateKeyFile, "JWTPrivateKey")
	if err != nil {
		return nil, err
	}
	block, err := parsePEMBlock(data, "JWTPrivateKey")
	if err != nil {
		return nil, err
	}

	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecKey, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not ECDSA")
		}
		return ecKey, nil
	}
	return nil, errors.New("failed to parse EC private key: expected SEC1 or PKCS8 PEM")
}

func loadECPublicKey(cfg types.SecurityConfig, priv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	if len(cfg.JWTPublicKeyPEM) == 0 && cfg.JWTPublicKeyFile == "" {
		return &priv.PublicKey, nil
	}
	data, err := readKeyMaterial(cfg.JWTPublicKeyPEM, cfg.JWTPublicKeyFile, "JWTPublicKey")
	if err != nil {
		return nil, err
	}
	block, err := parsePEMBlock(data, "JWTPublicKey")
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ecPub, nil
}

// --- KID derivation ---

func rsaKID(pub *rsa.PublicKey) string {
	h := sha256.New()
	h.Write(pub.N.Bytes())
	h.Write(big.NewInt(int64(pub.E)).Bytes())
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

func ecKID(pub *ecdsa.PublicKey) string {
	x, y, ok := ecCoordinates(pub)
	if !ok {
		return ""
	}
	// Leading zero bytes are trimmed so derived IDs match those computed from
	// big.Int coordinates by earlier releases; tokens they signed still verify.
	h := sha256.New()
	h.Write(bytes.TrimLeft(x, "\x00"))
	h.Write(bytes.TrimLeft(y, "\x00"))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

// ecCoordinates returns the affine coordinates of pub at the full size of the
// curve, as RFC 7518 section 6.2.1.2 requires for JWK "x" and "y".
func ecCoordinates(pub *ecdsa.PublicKey) (x, y []byte, ok bool) {
	if pub == nil {
		return nil, nil, false
	}
	point, err := pub.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil || len(point) < 3 || len(point)%2 == 0 || point[0] != 4 {
		return nil, nil, false
	}
	size := (len(point) - 1) / 2
	return point[1 : 1+size], point[1+size:], true
}

func base64urlBigInt(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

func base64urlInt(i int) string {
	b := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(b)
}
