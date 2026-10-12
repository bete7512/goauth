package models

//go:generate mockgen -destination=../../internal/mocks/mock_passkey_repository.go -package=mocks github.com/bete7512/goauth/pkg/models PasskeyRepository

import (
	"context"
	"time"
)

// PasskeyCredential is a registered WebAuthn credential (passkey) owned by a user.
// The credential material is stored verbatim as produced by the WebAuthn library
// so updates from future spec revisions can be picked up without schema changes.
type PasskeyCredential struct {
	ID                string     `json:"id" gorm:"primaryKey"`
	UserID            string     `json:"user_id" gorm:"not null;index"`
	CredentialID      []byte     `json:"credential_id" gorm:"uniqueIndex;not null"`
	PublicKey         []byte     `json:"public_key" gorm:"not null"`
	AttestationType   string     `json:"attestation_type"`
	AttestationFormat string     `json:"attestation_format"`
	AAGUID            []byte     `json:"aaguid"`
	SignCount         uint32     `json:"sign_count" gorm:"not null;default:0"`
	Transports        string     `json:"transports"` // comma-separated ("usb,nfc,internal,hybrid")
	BackupEligible    bool       `json:"backup_eligible" gorm:"not null;default:false"`
	BackupState       bool       `json:"backup_state" gorm:"not null;default:false"`
	UserPresent       bool       `json:"user_present" gorm:"not null;default:false"`
	UserVerified      bool       `json:"user_verified" gorm:"not null;default:false"`
	Name              string     `json:"name"` // user-friendly label ("iPhone 15", "YubiKey 5")
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (PasskeyCredential) TableName() string {
	return "passkey_credentials"
}

// PasskeyRepository manages PasskeyCredential persistence.
type PasskeyRepository interface {
	Create(ctx context.Context, cred *PasskeyCredential) error
	FindByID(ctx context.Context, id string) (*PasskeyCredential, error)
	FindByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyCredential, error)
	ListByUserID(ctx context.Context, userID string) ([]*PasskeyCredential, error)
	// UpdateSignCount atomically advances a nonzero counter; non-increasing
	// values conflict. Zero-to-zero is permitted for counterless authenticators.
	UpdateSignCount(ctx context.Context, id string, signCount uint32) error
	UpdateLastUsed(ctx context.Context, id string, at time.Time) error
	UpdateName(ctx context.Context, id, name string) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
