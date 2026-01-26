package models

import (
	"context"
	"time"
)

// AuditLog represents an audit log entry for admin actions
type AuditLog struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Action    string    `json:"action" gorm:"not null"`
	UserID    uint      `json:"user_id" gorm:"index"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}

// AuditLogRepository defines the interface for audit log operations
type AuditLogRepository interface {
	Create(ctx context.Context, log *AuditLog) error
	FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*AuditLog, error)
	List(ctx context.Context, limit, offset int) ([]*AuditLog, error)
}
