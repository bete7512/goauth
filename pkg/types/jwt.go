package types

// JWTAlgorithm is the signing algorithm used for access tokens and stateless refresh tokens.
// HS256 is symmetric (uses SecurityConfig.JwtSecretKey).
// RS256 and ES256 are asymmetric and require PEM-encoded key material via JWTPrivateKeyPEM/PEMFile.
type JWTAlgorithm string

// Supported JWT signing algorithms.
const (
	JWTAlgorithmHS256 JWTAlgorithm = "HS256"
	JWTAlgorithmRS256 JWTAlgorithm = "RS256"
	JWTAlgorithmES256 JWTAlgorithm = "ES256"
)

// IsAsymmetric reports whether the algorithm needs a public/private key pair.
func (a JWTAlgorithm) IsAsymmetric() bool {
	switch a {
	case JWTAlgorithmRS256, JWTAlgorithmES256:
		return true
	default:
		return false
	}
}

// JWK is one public key in JSON Web Key format (RFC 7517). Only the fields
// needed by relying parties are populated — private-key components are never
// included.
type JWK struct {
	Kty string `json:"kty"`           // "RSA" or "EC"
	Use string `json:"use,omitempty"` // "sig"
	Kid string `json:"kid,omitempty"` // key ID — matches JWT header "kid"
	Alg string `json:"alg,omitempty"` // "RS256", "ES256"

	// RSA public key components (Kty=="RSA")
	N string `json:"n,omitempty"` // modulus, base64url
	E string `json:"e,omitempty"` // exponent, base64url

	// EC public key components (Kty=="EC")
	Crv string `json:"crv,omitempty"` // "P-256"
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is the public JSON Web Key Set exposed at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}
