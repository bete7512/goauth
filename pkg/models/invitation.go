package models

//go:generate mockgen -destination=../../internal/mocks/mock_invitation_repository.go -package=mocks github.com/bete7512/goauth/pkg/models InvitationRepository

import (
	"context"
	"time"
)

// Invitation statuses (shared between standalone and org invitations).
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusDeclined = "declined"
	InvitationStatusExpired  = "expired"
)

// Invitation represents a standalone (non-org) invitation.
type Invitation struct {
	ID         string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Email      string     `json:"email" gorm:"type:varchar(255);not null"`
	Purpose    string     `json:"purpose" gorm:"type:varchar(100);not null;default:'platform'"`
	InviterID  string     `json:"inviter_id" gorm:"type:varchar(36);not null"`
	Token      string     `json:"-" gorm:"type:varchar(255);uniqueIndex;not null"`
	Status     string     `json:"status" gorm:"type:varchar(20);not null;default:'pending'"`
	Metadata   string     `json:"metadata,omitempty" gorm:"type:text"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

// InvitationRepository defines data access for standalone invitations.
type InvitationRepository interface {
	Create(ctx context.Context, invitation *Invitation) error
	FindByID(ctx context.Context, id string) (*Invitation, error)
	FindByToken(ctx context.Context, token string) (*Invitation, error)
	FindPendingByEmail(ctx context.Context, email, purpose string) (*Invitation, error)
	ListByInviter(ctx context.Context, inviterID string, opts InvitationListOpts) ([]*Invitation, int64, error)
	ListPendingByEmail(ctx context.Context, email string) ([]*Invitation, error)
	Update(ctx context.Context, invitation *Invitation) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
