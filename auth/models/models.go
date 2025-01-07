// auth/models.go
package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID               string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email            string         `json:"email" gorm:"uniqueIndex;not null"`
	Password         string         `json:"-" gorm:"not null"`
	FirstName        string         `json:"first_name"`
	LastName         string         `json:"last_name"`
	EmailVerified    bool           `json:"email_verified" gorm:"default:false"`
	TwoFactorSecret  string         `json:"-"`
	TwoFactorEnabled bool           `json:"two_factor_enabled" gorm:"default:false"`
	IsAdmin          bool           `json:"is_admin" gorm:"default:false"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `json:"-" gorm:"index"`
}

type Session struct {
	ID           string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID       string    `gorm:"type:uuid;not null"`
	RefreshToken string    `gorm:"not null"`
	ExpiresAt    time.Time `gorm:"not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
