package models

import (
	"context"
	"time"
)

type VerificationTokenType string

// Token types
const (
	TokenTypeEmailVerification VerificationTokenType = "email_verification"
	TokenTypePhoneVerification VerificationTokenType = "phone_verification"
	TokenTypePasswordReset     VerificationTokenType = "password_reset"
	TokenTypeTwoFactorCode     VerificationTokenType = "two_factor_code"
)

// VerificationToken represents a token for email/phone verification or password reset
type VerificationToken struct {
	ID          string                `json:"id" gorm:"primaryKey"`
	UserID      string                `json:"user_id" gorm:"index;not null"`
	Token       string                `json:"token" gorm:"uniqueIndex;not null"`
	Code        string                `json:"code" gorm:"index"`    // For OTP-style verification
	Type        VerificationTokenType `json:"type" gorm:"not null"` // email_verification, phone_verification, password_reset
	Email       string                `json:"email" gorm:"index"`
	PhoneNumber string                `json:"phone_number" gorm:"index"`
	ExpiresAt   time.Time             `json:"expires_at" gorm:"not null"`
	Used        bool                  `json:"used" gorm:"default:false"`
	UsedAt      *time.Time            `json:"used_at"`
	CreatedAt   time.Time             `json:"created_at"`
}

// VerificationTokenRepository interface for token operations
type VerificationTokenRepository interface {
	Create(ctx context.Context, token *VerificationToken) error
	FindByToken(ctx context.Context, token string) (*VerificationToken, error)
	FindByCode(ctx context.Context, code, tokenType string) (*VerificationToken, error)
	FindByEmailAndType(ctx context.Context, email, tokenType string) (*VerificationToken, error)
	FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*VerificationToken, error)
	MarkAsUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
	Delete(ctx context.Context, id string, tokenType string) error
}

func (VerificationToken) TableName() string {
	return "verification_tokens"
}
