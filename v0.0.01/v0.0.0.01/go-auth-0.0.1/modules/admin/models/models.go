package models

import "time"

type AuditLog struct {
	ID        uint      `gorm:"primaryKey"`
	Action    string    `gorm:"not null"`
	UserID    uint      `gorm:"not null"`
	Timestamp time.Time `gorm:"autoCreateTime"`
	Details   string    `gorm:"type:text"`
}

type Setting struct {
	ID        uint      `gorm:"primaryKey"`
	Key       string    `gorm:"unique;not null"`
	Value     string    `gorm:"type:text;not null"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
