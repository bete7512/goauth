package models

//go:generate mockgen -destination=../../internal/mocks/mock_idp_repository.go -package=mocks github.com/bete7512/goauth/pkg/models IDPClientRepository,IDPGrantRepository

import (
	"context"
	"time"
)

// Token types of the identity provider (idp) module: a pending authorization
// request, an authorization code, an access token and a refresh token. The
// records are stored as digests in the core token store.
const (
	TokenTypeIDPRequest = "idp_request"
	TokenTypeIDPCode    = "idp_code"
	TokenTypeIDPAccess  = "idp_access"
	TokenTypeIDPRefresh = "idp_refresh"
)

// IDPClient is an application that signs users in through the idp module: an
// OpenID Connect relying party. ClientID is the public identifier the
// application sends; ID is the internal row identifier.
type IDPClient struct {
	ID       string `json:"id" gorm:"column:id;primaryKey"`
	ClientID string `json:"client_id" gorm:"column:client_id;uniqueIndex;not null"`
	Name     string `json:"name" gorm:"column:name;not null"`
	// SecretHash is the digest of the client secret, never the secret. It is
	// empty for a public client.
	SecretHash string `json:"-" gorm:"column:secret_hash"`
	// Public marks a client that cannot keep a secret (a browser or mobile
	// application). It authenticates with PKCE alone.
	Public       bool       `json:"public" gorm:"column:is_public"`
	RedirectURIs StringList `json:"redirect_uris" gorm:"column:redirect_uris;type:text"`
	// Scopes limits what the client may request.
	Scopes StringList `json:"scopes" gorm:"column:scopes;type:text"`
	// RequirePKCE rejects authorization requests without a PKCE challenge.
	// It is always true for a public client.
	RequirePKCE bool `json:"require_pkce" gorm:"column:require_pkce"`
	// SkipConsent marks an application the host operates itself: the user is
	// not asked to approve it.
	SkipConsent bool   `json:"skip_consent" gorm:"column:skip_consent"`
	LogoURI     string `json:"logo_uri,omitempty" gorm:"column:logo_uri"`
	ClientURI   string `json:"client_uri,omitempty" gorm:"column:client_uri"`
	// Managed marks a client declared in configuration. It is rewritten from
	// configuration at every start and cannot be changed through the API.
	Managed    bool       `json:"managed" gorm:"column:managed"`
	Disabled   bool       `json:"disabled" gorm:"column:disabled"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" gorm:"column:last_used_at"`
	CreatedAt  time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt  time.Time  `json:"updated_at" gorm:"column:updated_at"`
}

// TableName returns the database table name.
func (IDPClient) TableName() string {
	return "idp_clients"
}

// IDPGrant records that a user allowed a client to sign them in, and with
// which scopes. There is one grant per user and client. Every token issued to
// the client for the user names the grant, so deleting it ends them all.
type IDPGrant struct {
	ID         string     `json:"id" gorm:"column:id;primaryKey"`
	UserID     string     `json:"user_id" gorm:"column:user_id;not null;uniqueIndex:idx_idp_grants_user_client"`
	ClientID   string     `json:"client_id" gorm:"column:client_id;not null;uniqueIndex:idx_idp_grants_user_client;index"`
	Scopes     StringList `json:"scopes" gorm:"column:scopes;type:text"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty" gorm:"column:last_used_at"`
	CreatedAt  time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt  time.Time  `json:"updated_at" gorm:"column:updated_at"`
}

// TableName returns the database table name.
func (IDPGrant) TableName() string {
	return "idp_grants"
}

// IDPClientRepository persists idp clients.
type IDPClientRepository interface {
	Create(ctx context.Context, client *IDPClient) error
	// Update saves every field of an existing client.
	Update(ctx context.Context, client *IDPClient) error
	FindByID(ctx context.Context, id string) (*IDPClient, error)
	// FindByClientID finds a client by its public identifier, which is
	// case-sensitive.
	FindByClientID(ctx context.Context, clientID string) (*IDPClient, error)
	FindByClientIDs(ctx context.Context, clientIDs []string) ([]*IDPClient, error)
	List(ctx context.Context, opts IDPClientListOpts) ([]*IDPClient, int64, error)
	Delete(ctx context.Context, id string) error
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

// IDPGrantRepository persists idp grants.
type IDPGrantRepository interface {
	// Create inserts a grant. It returns ErrConflict when the user already
	// has a grant for the client.
	Create(ctx context.Context, grant *IDPGrant) error
	// Update saves the scopes of an existing grant.
	Update(ctx context.Context, grant *IDPGrant) error
	FindByID(ctx context.Context, id string) (*IDPGrant, error)
	FindByUserAndClient(ctx context.Context, userID, clientID string) (*IDPGrant, error)
	List(ctx context.Context, opts IDPGrantListOpts) ([]*IDPGrant, int64, error)
	Delete(ctx context.Context, id string) error
	// DeleteByClient removes every grant of a client and returns how many.
	DeleteByClient(ctx context.Context, clientID string) (int64, error)
	// DeleteByUser removes every grant of a user and returns how many.
	DeleteByUser(ctx context.Context, userID string) (int64, error)
	TouchLastUsed(ctx context.Context, id string, at time.Time) error
}

// IDPClientListOpts extends ListingOpts with client filters.
type IDPClientListOpts struct {
	ListingOpts
	Query   string // search name and client_id
	Managed *bool  // filter clients declared in configuration (true) or not (false)
}

// Normalize validates and clamps all fields.
func (o *IDPClientListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, idpClientSortFields)
}

// IDPGrantListOpts extends ListingOpts with grant filters.
type IDPGrantListOpts struct {
	ListingOpts
	UserID   string
	ClientID string
}

// Normalize validates and clamps all fields.
func (o *IDPGrantListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, idpGrantSortFields)
}

var idpClientSortFields = map[string]bool{
	"created_at":   true,
	"name":         true,
	"last_used_at": true,
}

var idpGrantSortFields = map[string]bool{
	"created_at":   true,
	"last_used_at": true,
}
