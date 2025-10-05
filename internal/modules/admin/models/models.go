package models

import (
	"context"
	"time"
)

type AuditLog struct {
	ID        uint      `gorm:"primaryKey"`
	Action    string    `gorm:"not null"`
	UserID    uint      `gorm:"not null"`
	Timestamp time.Time `gorm:"autoCreateTime"`
	Details   string    `gorm:"type:text"`
}

type AuditLogRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, limit, offset int) ([]*AuditLog, error)
	FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*AuditLog, error)
	FindByAction(ctx context.Context, action string, limit, offset int) ([]*AuditLog, error)
}
