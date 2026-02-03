package models

//go:generate mockgen -destination=../../internal/mocks/mock_auditlog_repository.go -package=mocks github.com/bete7512/goauth/pkg/models AuditLogRepository

import (
	"context"
	"time"
)

// AuditLog represents an audit log entry for tracking all system actions
// This is a cross-cutting concern used by all modules (core, admin, audit, org, etc.)
type AuditLog struct {
	ID             string     `json:"id" gorm:"primaryKey"`
	Action         string     `json:"action" gorm:"not null;index"`           // e.g., "auth.login", "admin.user.delete"
	ActorID        string     `json:"actor_id" gorm:"not null;index"`         // User who performed the action
	ActorType      string     `json:"actor_type" gorm:"default:'user'"`       // "user", "admin", "system"
	TargetID       *string    `json:"target_id,omitempty" gorm:"index"`       // Resource affected (optional)
	TargetType     *string    `json:"target_type,omitempty"`                  // "user", "organization", "resource"
	OrganizationID *string    `json:"organization_id,omitempty" gorm:"index"` // For multi-tenant context (future)
	Details        string     `json:"details" gorm:"type:text"`               // Human-readable description
	Metadata       string     `json:"metadata,omitempty" gorm:"type:jsonb"`   // JSON: {ip, user_agent, device, location}
	Severity       string     `json:"severity" gorm:"default:'info';index"`   // "info", "warning", "critical"
	IPAddress      string     `json:"ip_address"`
	UserAgent      string     `json:"user_agent"`
	CreatedAt      time.Time  `json:"created_at" gorm:"index"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}

// AuditLogRepository defines the interface for audit log operations
type AuditLogRepository interface {
	// Create creates a new audit log entry
	Create(ctx context.Context, log *AuditLog) error

	// FindByActorID finds audit logs by the user who performed actions
	FindByActorID(ctx context.Context, actorID string, limit, offset int) ([]*AuditLog, error)

	// FindByTargetID finds audit logs where the user was the target of actions
	FindByTargetID(ctx context.Context, targetID string, limit, offset int) ([]*AuditLog, error)

	// FindByAction finds audit logs by action type
	FindByAction(ctx context.Context, action string, limit, offset int) ([]*AuditLog, error)

	// FindBySeverity finds audit logs by severity level
	FindBySeverity(ctx context.Context, severity string, limit, offset int) ([]*AuditLog, error)

	// FindByOrganizationID finds audit logs for an organization (future)
	FindByOrganizationID(ctx context.Context, orgID string, limit, offset int) ([]*AuditLog, error)

	// List retrieves all audit logs with pagination
	List(ctx context.Context, limit, offset int) ([]*AuditLog, error)

	// DeleteOlderThan deletes audit logs older than the specified time
	DeleteOlderThan(ctx context.Context, before time.Time) error

	// DeleteByActionOlderThan deletes audit logs for specific action older than specified time
	DeleteByActionOlderThan(ctx context.Context, action string, before time.Time) error
}
