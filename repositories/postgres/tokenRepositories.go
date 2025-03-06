package postgres

import (
	"time"

	"github.com/bete7512/goauth/interfaces"
	"gorm.io/gorm"
)

type TokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) interfaces.TokenRepository {
	return &TokenRepository{db: db}
}

// InvalidateAllRefreshTokens implements interfaces.TokenRepository.
func (t *TokenRepository) InvalidateAllRefreshTokens(userID string) error {
	panic("unimplemented")
}

// InvalidateEmailVerificationToken implements interfaces.TokenRepository.
func (t *TokenRepository) InvalidateEmailVerificationToken(userID string, token string) error {
	panic("unimplemented")
}

// InvalidatePasswordResetToken implements interfaces.TokenRepository.
func (t *TokenRepository) InvalidatePasswordResetToken(token string) error {
	panic("unimplemented")
}

// InvalidateRefreshToken implements interfaces.TokenRepository.
func (t *TokenRepository) InvalidateRefreshToken(userID string, token string) error {
	panic("unimplemented")
}

// InvalidateTwoFactorCode implements interfaces.TokenRepository.
func (t *TokenRepository) InvalidateTwoFactorCode(userID string, code string) error {
	panic("unimplemented")
}

// SaveEmailVerificationToken implements interfaces.TokenRepository.
func (t *TokenRepository) SaveEmailVerificationToken(userID string, token string, expiry time.Duration) error {
	panic("unimplemented")
}

// SavePasswordResetToken implements interfaces.TokenRepository.
func (t *TokenRepository) SavePasswordResetToken(userID string, token string, expiry time.Duration) error {
	panic("unimplemented")
}

// SaveRefreshToken implements interfaces.TokenRepository.
func (t *TokenRepository) SaveRefreshToken(userID string, token string, expiry time.Duration) error {
	panic("unimplemented")
}

// SaveTwoFactorCode implements interfaces.TokenRepository.
func (t *TokenRepository) SaveTwoFactorCode(userID string, code string, expiry time.Duration) error {
	panic("unimplemented")
}

// ValidateEmailVerificationToken implements interfaces.TokenRepository.
func (t *TokenRepository) ValidateEmailVerificationToken(userID string, token string) (bool, error) {
	panic("unimplemented")
}

// ValidatePasswordResetToken implements interfaces.TokenRepository.
func (t *TokenRepository) ValidatePasswordResetToken(token string) (bool, string, error) {
	panic("unimplemented")
}

// ValidateRefreshToken implements interfaces.TokenRepository.
func (t *TokenRepository) ValidateRefreshToken(userID string, token string) (bool, error) {
	panic("unimplemented")
}

// ValidateTwoFactorCode implements interfaces.TokenRepository.
func (t *TokenRepository) ValidateTwoFactorCode(userID string, code string) (bool, error) {
	panic("unimplemented")
}
