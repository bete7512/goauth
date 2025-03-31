// auth/models.go
package models

import (
	"time"

	"gorm.io/gorm"
)

type TokenType string

const (
	RefreshToken           TokenType = "refresh"
	EmailVerificationToken TokenType = "email_verification"
	PasswordResetToken     TokenType = "password_reset"
	TwoFactorCode          TokenType = "two_factor"
	MakicLinkToken         TokenType = "magic_link"
)

type User struct {
	ID                string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	FirstName         string         `json:"first_name" swagger:"required example=John"`
	LastName          string         `json:"last_name"`
	Email             string         `json:"email" gorm:"uniqueIndex;not null"`
	PhoneNumber       *string        `json:"phone_number" gorm:"unique;"`
	Password          string         `json:"-" gorm:"not null"`
	EmailVerified     bool           `json:"email_verified" gorm:"default:false"`
	TwoFactorEnabled  bool           `json:"two_factor_enabled" gorm:"default:false"`
	TwoFactorVerified bool           `json:"two_factor_verified" gorm:"default:false"`
	Active            bool           `json:"active" gorm:"default:true"`
	IsAdmin           bool           `json:"is_admin" gorm:"default:false"`
	Avatar            *string        `json:"avatar"`
	ProviderId        *string        `json:"provider_id"`
	CreatedAt         time.Time      `json:"created_at"`
	SigninVia         string         `json:"signin_via"`
	UpdatedAt         time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	LastLoginAt       *time.Time     `json:"last_login_at,omitempty"`
	DeletedAt         gorm.DeletedAt `json:"-" gorm:"index"`
}
type Token struct {
	ID         string    `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID     string    `gorm:"index"`
	TokenType  TokenType `gorm:"index"`
	TokenValue string    `gorm:"index"`
	ExpiresAt  time.Time `gorm:"index"`
	Used       bool      `gorm:"default:false"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}
