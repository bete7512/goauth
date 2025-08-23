package handlers

import (
	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// AuthHandler handles HTTP requests for authentication
type AuthHandler struct {
	Auth        *config.Auth
	authService interfaces.Service
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(auth *config.Auth) *AuthHandler {
	service := services.NewAuthService(auth)
	return &AuthHandler{
		authService: service,
		Auth:        auth,
	}
}

