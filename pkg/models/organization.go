package models

import (
	"context"
	"time"
)

// Organization represents an organization/workspace/team.
type Organization struct {
	ID        string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Name      string     `json:"name" gorm:"type:varchar(255);not null"`
	Slug      string     `json:"slug" gorm:"type:varchar(255);uniqueIndex;not null"`
	OwnerID   string     `json:"owner_id" gorm:"type:varchar(36);not null"`
	LogoURL   string     `json:"logo_url,omitempty" gorm:"type:varchar(512)"`
	Metadata  string     `json:"metadata,omitempty" gorm:"type:text"`
	Active    bool       `json:"active" gorm:"default:true"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// OrganizationMember represents a user's membership in an organization.
type OrganizationMember struct {
	ID        string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID     string     `json:"org_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_org_member"`
	UserID    string     `json:"user_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_org_member"`
	Role      string     `json:"role" gorm:"type:varchar(50);not null;default:'member'"`
	JoinedAt  time.Time  `json:"joined_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// Invitation represents a pending invitation to join an organization.
type Invitation struct {
	ID         string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID      string     `json:"org_id" gorm:"type:varchar(36);not null"`
	Email      string     `json:"email" gorm:"type:varchar(255);not null"`
	Role       string     `json:"role" gorm:"type:varchar(50);not null;default:'member'"`
	InviterID  string     `json:"inviter_id" gorm:"type:varchar(36);not null"`
	Token      string     `json:"-" gorm:"type:varchar(255);uniqueIndex;not null"`
	Status     string     `json:"status" gorm:"type:varchar(20);not null;default:'pending'"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

// Invitation statuses
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusDeclined = "declined"
	InvitationStatusExpired  = "expired"
)

// OrganizationRepository defines data access for organizations.
type OrganizationRepository interface {
	Create(ctx context.Context, org *Organization) error
	FindByID(ctx context.Context, id string) (*Organization, error)
	FindBySlug(ctx context.Context, slug string) (*Organization, error)
	FindByOwnerID(ctx context.Context, ownerID string) ([]*Organization, error)
	List(ctx context.Context, opts OrganizationListOpts) ([]*Organization, int64, error)
	Update(ctx context.Context, org *Organization) error
	Delete(ctx context.Context, id string) error
	IsSlugAvailable(ctx context.Context, slug string) (bool, error)
}

// OrganizationMemberRepository defines data access for organization memberships.
type OrganizationMemberRepository interface {
	Create(ctx context.Context, member *OrganizationMember) error
	FindByOrgAndUser(ctx context.Context, orgID, userID string) (*OrganizationMember, error)
	ListByOrg(ctx context.Context, orgID string, opts MemberListOpts) ([]*OrganizationMember, int64, error)
	ListByUser(ctx context.Context, userID string) ([]*OrganizationMember, error)
	Update(ctx context.Context, member *OrganizationMember) error
	Delete(ctx context.Context, id string) error
	DeleteByOrgAndUser(ctx context.Context, orgID, userID string) error
	CountByOrg(ctx context.Context, orgID string) (int64, error)
}

// InvitationRepository defines data access for organization invitations.
type InvitationRepository interface {
	Create(ctx context.Context, invitation *Invitation) error
	FindByID(ctx context.Context, id string) (*Invitation, error)
	FindByToken(ctx context.Context, token string) (*Invitation, error)
	FindByOrgAndEmail(ctx context.Context, orgID, email string) (*Invitation, error)
	ListByOrg(ctx context.Context, orgID string, opts InvitationListOpts) ([]*Invitation, int64, error)
	ListPendingByEmail(ctx context.Context, email string) ([]*Invitation, error)
	Update(ctx context.Context, invitation *Invitation) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
