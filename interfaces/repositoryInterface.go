package interfaces

import (
	"time"

	"github.com/bete7512/goauth/models"
)

type UserRepository interface {
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	UpdateUser(user *models.User) error
	UpsertUserByEmail(user *models.User) error
	DeleteUser(user *models.User) error
}

type TokenRepository interface {
	// Refresh tokens
	SaveRefreshToken(userID, token string, expiry time.Duration) error
	ValidateRefreshToken(userID, token string) (bool, error)
	InvalidateRefreshToken(userID, token string) error
	InvalidateAllRefreshTokens(userID string) error

	// Email verification tokens
	SaveEmailVerificationToken(userID, token string, expiry time.Duration) error
	ValidateEmailVerificationToken(userID, token string) (bool, error)
	InvalidateEmailVerificationToken(userID, token string) error

	// Password reset tokens
	SavePasswordResetToken(userID, token string, expiry time.Duration) error
	ValidatePasswordResetToken(token string) (bool, string, error)
	InvalidatePasswordResetToken(token string) error

	// Two-factor auth codes
	SaveTwoFactorCode(userID, code string, expiry time.Duration) error
	ValidateTwoFactorCode(userID, code string) (bool, error)
	InvalidateTwoFactorCode(userID, code string) error

	// Magic link tokens

	SaveMagicLinkToken(userID, token string, expiry time.Duration) error
	ValidateMagicLinkToken(token string) (bool, string, error)
}
type RepositoryFactory interface {
	GetUserRepository() UserRepository
	GetTokenRepository() TokenRepository
}
