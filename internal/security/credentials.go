package security

import (
	"errors"
	"github.com/bete7512/goauth/pkg/types"
)

func reservedClaim(name string) bool {
	switch name {
	case "user_id", "sub", "iss", "aud", "type", "exp", "iat", "nbf", "jti", "token_version":
		return true
	}
	return false
}

// IsReservedClaim protects engine-owned identity and assurance from extensions.
func IsReservedClaim(name string) bool {
	return reservedClaim(name) || name == "session_id" || name == "auth_time" || name == "amr" || name == "acr"
}

// ValidateCredential requires a credential purpose in addition to cryptographic
// validation. Never use generic JWT validation as an authorization decision.
func ValidateCredential(manager types.SecurityManager, token, purpose string) (map[string]interface{}, error) {
	claims, err := manager.ValidateJWTToken(token)
	if err != nil {
		return nil, err
	}
	if claims["type"] != purpose {
		return nil, errors.New("invalid credential purpose")
	}
	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" || claims["sub"] != userID {
		return nil, errors.New("invalid credential subject")
	}
	return claims, nil
}
