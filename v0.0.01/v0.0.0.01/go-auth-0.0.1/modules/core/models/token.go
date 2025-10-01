package models

import "time"

type Token struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"not null;index"`
	Type      string    `json:"type" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	Used      bool      `json:"used" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`

	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}
