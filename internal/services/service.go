package services

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

// AuthService implements the AuthService interface
type AuthService struct {
	Auth *config.Auth
}

// NewAuthService creates a new auth service
func NewAuthService(auth *config.Auth) interfaces.Service {
	return &AuthService{
		Auth: auth,
	}
}
