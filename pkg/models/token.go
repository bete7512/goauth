package models

//go:generate mockgen -destination=../../internal/mocks/mock_token_repository.go -package=mocks github.com/bete7512/goauth/pkg/models TokenRepository,RotatingTokenRepository

import (
	"context"
	"time"
)

// Token type constants for all token-based flows.
const (
	TokenTypeEmailVerification = "email_verification"
	TokenTypePhoneVerification = "phone_verification"
	TokenTypePasswordReset     = "password_reset"
	TokenTypeTwoFactorCode     = "two_factor_code"
	TokenTypeMagicLink         = "magic_link"
	TokenTypeOAuthState        = "oauth_state"
)

// Token is a stored credential record with a type, an owner, an expiry and a
// single-use state: verification, password-reset, magic-link and OAuth state
// tokens, refresh nonces, short codes and authentication continuations.
type Token struct {
	// Data stores typed, purpose-specific continuation state; never serialize it.
	Data        string     `json:"-" gorm:"type:text"`
	ID          string     `json:"id" gorm:"primaryKey"`
	UserID      string     `json:"user_id" gorm:"not null;index"`
	Type        string     `json:"type" gorm:"not null;index"`
	Token       string     `json:"token" gorm:"uniqueIndex;not null"`
	Code        string     `json:"code,omitempty" gorm:"index"`
	Email       string     `json:"email,omitempty" gorm:"index"`
	PhoneNumber string     `json:"phone_number,omitempty" gorm:"index"`
	ExpiresAt   time.Time  `json:"expires_at" gorm:"not null;index"`
	Used        bool       `json:"used" gorm:"default:false"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	CreatedAt   time.Time  `json:"created_at"`
}

// TokenRepository persists Token records.
type TokenRepository interface {
	Create(ctx context.Context, token *Token) error
	FindByToken(ctx context.Context, token string) (*Token, error)
	FindByUserID(ctx context.Context, userID string) ([]*Token, error)
	FindByCode(ctx context.Context, code, tokenType string) (*Token, error)
	FindByEmailAndType(ctx context.Context, email, tokenType string) (*Token, error)
	FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*Token, error)
	IncrementAttempts(ctx context.Context, id string) (int, error)
	// MarkAsUsed atomically consumes an unused, unexpired token. Exactly one
	// concurrent caller succeeds; all others receive ErrConflict.
	MarkAsUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, token string) error
	DeleteByIDAndType(ctx context.Context, id string, tokenType string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// TokenRotator is an optional atomic capability required for refresh rotation.
// The replacement is committed iff the expected live token was consumed.
type TokenRotator interface {
	Rotate(ctx context.Context, expected *Token, replacement *Token) error
}

// RotatingTokenRepository is a TokenRepository that rotates a refresh record
// atomically.
type RotatingTokenRepository interface {
	TokenRepository
	TokenRotator
}

// TableName returns the database table name.
func (Token) TableName() string {
	return "tokens"
}
