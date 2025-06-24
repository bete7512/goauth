package types

// CustomJWTClaimsProvider defines the interface for custom JWT claims
type CustomJWTClaimsProvider interface {
	GetClaims(user interface{}) (map[string]interface{}, error)
}
