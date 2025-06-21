// auth/models.go
package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type TokenType string

type TwoFactorMethod string

const (
	TwoFactorMethodEmail TwoFactorMethod = "email"
	TwoFactorMethodSMS   TwoFactorMethod = "sms"
	TwoFactorMethodTOTP  TwoFactorMethod = "totp"
	TwoFactorMethodPush  TwoFactorMethod = "push"
)
const (
	RefreshToken           TokenType = "refresh"
	EmailVerificationToken TokenType = "email_verification"
	PhoneVerificationToken TokenType = "phone_verification"
	PasswordResetToken     TokenType = "password_reset"
	TwoFactorCode          TokenType = "two_factor"
	MakicLinkToken         TokenType = "magic_link"
)

type User struct {
	ID            string  `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	FirstName     string  `json:"first_name" swagger:"required example=John"`
	LastName      string  `json:"last_name"`
	Email         string  `json:"email" gorm:"uniqueIndex;not null"`
	PhoneNumber   *string `json:"phone_number" gorm:"unique;"`
	Password      string  `json:"-" gorm:"not null"`
	EmailVerified bool    `json:"email_verified" gorm:"default:false"`
	PhoneVerified bool    `json:"phone_verified" gorm:"default:false"`

	// 2FA configuration
	TwoFactorEnabled        bool            `json:"two_factor_enabled" gorm:"default:false"`
	EnabledTwoFactorMethods datatypes.JSON  `json:"enabled_two_factor_methods" gorm:"type:jsonb"`
	DefaultTwoFactorMethod  TwoFactorMethod `json:"default_two_factor_method" gorm:"default:email"`

	Active      bool           `json:"active" gorm:"default:true"`
	IsAdmin     bool           `json:"is_admin" gorm:"default:false"`
	Avatar      *string        `json:"avatar"`
	ProviderId  *string        `json:"provider_id"`
	CreatedAt   time.Time      `json:"created_at"`
	SignedUpVia string         `json:"signed_up_via" gorm:"default:email"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	LastLoginAt *time.Time     `json:"last_login_at,omitempty"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
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

type AccountToken struct {
	ID           string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID       string         `json:"user_id" gorm:"index;not null"` // Reference to local user
	Provider     string         ` gorm:"index;not null"`               // e.g., google, github
	AccessToken  string         `gorm:"not null"`                      // The token from the provider
	RefreshToken *string        `gorm:""`                              // Optional, if provided
	ExpiresAt    *time.Time     `gorm:"index"`                         // Token expiry (nullable if no expiry)
	Scopes       *string        `gorm:"type:text"`                     // Optional scopes (e.g., profile,email)
	TokenType    *string        `gorm:"type:text"`                     // e.g., Bearer
	CreatedAt    time.Time      `gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `gorm:"autoUpdateTime"`
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

type AuditLog struct {
	ID        string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string         `json:"user_id" gorm:"index"`
	EventType string         `json:"event_type" gorm:"index"`
	Details   datatypes.JSON `json:"details" gorm:"type:jsonb"`
	IP        string         `json:"ip" gorm:"index"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

type TotpSecret struct {
	ID        string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string         `json:"user_id" gorm:"index;not null;unique"`
	Secret    string         `json:"-" gorm:"not null"` // Encrypted TOTP secret
	BackupURL string         `json:"-" gorm:"not null"` // QR code backup
	Verified  bool           `json:"verified" gorm:"default:false"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// Backup codes for 2FA recovery
type BackupCode struct {
	ID        string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID    string         `json:"user_id" gorm:"index;not null"`
	Code      string         `json:"-" gorm:"not null;unique"` // Hashed backup code
	Used      bool           `json:"used" gorm:"default:false"`
	UsedAt    *time.Time     `json:"used_at"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
