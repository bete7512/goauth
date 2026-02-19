package models

import "time"

// TwoFactor stores 2FA configuration for a user
type TwoFactor struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"uniqueIndex;not null"`
	Secret    string    `json:"-" gorm:"not null"` // TOTP secret (encrypted in storage)
	Enabled   bool      `json:"enabled" gorm:"default:false"`
	Verified  bool      `json:"verified" gorm:"default:false"`
	Method    string    `json:"method" gorm:"default:'totp'"` // totp, sms, email
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (TwoFactor) TableName() string {
	return "two_factors"
}

// BackupCode stores backup codes for 2FA recovery
type BackupCode struct {
	ID        string     `json:"id" gorm:"primaryKey"`
	UserID    string     `json:"user_id" gorm:"index;not null"`
	Code      string     `json:"-" gorm:"not null"` // Hashed with bcrypt
	Used      bool       `json:"used" gorm:"default:false"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (BackupCode) TableName() string {
	return "backup_codes"
}
