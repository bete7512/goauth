package models

//go:generate mockgen -destination=../../internal/mocks/mock_account_repository.go -package=mocks github.com/bete7512/goauth/pkg/models AccountRepository

import (
	"context"
	"time"
)

// AccountType represents the type of authentication account
type AccountType string

const (
	AccountTypeOAuth       AccountType = "oauth"
	AccountTypeOIDC        AccountType = "oidc"
	AccountTypeCredentials AccountType = "credentials"
)

// Account represents an OAuth/OIDC provider link for a user.
// A user can have multiple accounts (e.g., Google + GitHub).
// This model is only created when the OAuth module is used.
type Account struct {
	ID                string     `json:"id" gorm:"primaryKey"`
	UserID            string     `json:"user_id" gorm:"not null;index"`
	Provider          string     `json:"provider" gorm:"not null;index"`          // google, github, microsoft, discord
	ProviderAccountID string     `json:"provider_account_id" gorm:"not null"`     // Provider's unique user ID
	Type              string     `json:"type" gorm:"not null"`                    // oauth, oidc
	AccessToken       string     `json:"-" gorm:"type:text"`                      // Encrypted provider access token
	RefreshToken      string     `json:"-" gorm:"type:text"`                      // Encrypted provider refresh token
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`                    // Provider token expiry
	TokenType         string     `json:"token_type,omitempty"`                    // Usually "Bearer"
	Scope             string     `json:"scope,omitempty"`                         // Granted scopes
	IDToken           string     `json:"-" gorm:"type:text"`                      // OIDC ID token (for reference)
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (Account) TableName() string {
	return "accounts"
}

// AccountRepository defines the interface for account persistence
type AccountRepository interface {
	// Create creates a new account
	Create(ctx context.Context, account *Account) error

	// FindByID finds an account by its ID
	FindByID(ctx context.Context, id string) (*Account, error)

	// FindByProviderAndAccountID finds an account by provider and provider's user ID
	// This is the primary lookup method for OAuth login
	FindByProviderAndAccountID(ctx context.Context, provider, providerAccountID string) (*Account, error)

	// FindByUserID finds all accounts for a user
	FindByUserID(ctx context.Context, userID string) ([]*Account, error)

	// FindByUserIDAndProvider finds a specific provider account for a user
	FindByUserIDAndProvider(ctx context.Context, userID, provider string) (*Account, error)

	// Update updates an account (e.g., refresh tokens)
	Update(ctx context.Context, account *Account) error

	// Delete deletes an account by ID
	Delete(ctx context.Context, id string) error

	// DeleteByUserIDAndProvider deletes a user's account for a specific provider
	DeleteByUserIDAndProvider(ctx context.Context, userID, provider string) error

	// CountByUserID counts the number of accounts for a user
	CountByUserID(ctx context.Context, userID string) (int64, error)
}
