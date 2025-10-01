package models

import "time"

type TwoFactor struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	UserID      string     `json:"user_id" gorm:"not null;uniqueIndex"`
	Secret      string     `json:"-" gorm:"not null"`
	Enabled     bool       `json:"enabled" gorm:"default:false"`
	BackupCodes string     `json:"-" gorm:"type:text"`
	VerifiedAt  *time.Time `json:"verified_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (TwoFactor) TableName() string {
	return "two_factor"
}
