package models

//go:generate mockgen -destination=../../internal/mocks/mock_token_repository.go -package=mocks github.com/bete7512/goauth/pkg/models TokenRepository

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
)

type Token struct {
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
	CreatedAt   time.Time  `json:"created_at"`
}

type TokenRepository interface {
	Create(ctx context.Context, token *Token) error
	FindByToken(ctx context.Context, token string) (*Token, error)
	FindByUserID(ctx context.Context, userID string) ([]*Token, error)
	FindByCode(ctx context.Context, code, tokenType string) (*Token, error)
	FindByEmailAndType(ctx context.Context, email, tokenType string) (*Token, error)
	FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*Token, error)
	MarkAsUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, token string) error
	DeleteByIDAndType(ctx context.Context, id string, tokenType string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}

func (Token) TableName() string {
	return "tokens"
}
