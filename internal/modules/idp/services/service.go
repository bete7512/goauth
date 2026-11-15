// Package services implements the OpenID Connect provider behind the idp
// module: client applications and their authentication, the authorization
// code flow with consent on the host's frontend, the token endpoint, the
// UserInfo endpoint, the discovery document, and the administration of
// clients and grants.
package services

//go:generate mockgen -destination=../../../mocks/mock_idp_service.go -package=mocks github.com/bete7512/goauth/internal/modules/idp/services IDPService

import (
	"context"
	"net/url"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/operation"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// IDPService is the OpenID Connect provider behind the HTTP handlers.
// Methods that back protocol endpoints (Authorize, Token, UserInfo) return
// errors whose Code is an OAuth error code (see the Code constants); the
// others use GoAuth codes.
type IDPService interface {
	// Discovery returns the OpenID Provider metadata.
	Discovery() dto.DiscoveryDocument
	// JWKS returns the public keys that verify ID tokens.
	JWKS() types.JWKS

	// Authorize validates an authorization request and returns where to send
	// the browser: the consent page, or the client's redirect URI with an
	// error. An error return means the request cannot be answered through a
	// redirect.
	Authorize(ctx context.Context, query url.Values) (string, *types.GoAuthError)
	// ConsentDetails describes a pending request to the signed-in user.
	ConsentDetails(ctx context.Context, principal types.Principal, requestID string) (*dto.ConsentDetails, *types.GoAuthError)
	// ApproveConsent records the user's approval and returns the client
	// redirect carrying the authorization code.
	ApproveConsent(ctx context.Context, principal types.Principal, requestID string, metadata *types.RequestMetadata) (string, *types.GoAuthError)
	// DenyConsent records the refusal and returns the client redirect
	// carrying access_denied.
	DenyConsent(ctx context.Context, userID, requestID string, metadata *types.RequestMetadata) (string, *types.GoAuthError)

	// Token serves the token endpoint.
	Token(ctx context.Context, req *TokenRequest) (*dto.TokenResponse, *types.GoAuthError)
	// UserInfo returns the claims an access token releases.
	UserInfo(ctx context.Context, accessToken string) (map[string]interface{}, *types.GoAuthError)

	// ListGrants lists the applications the user is connected to.
	ListGrants(ctx context.Context, userID string, opts models.IDPGrantListOpts) ([]dto.Grant, int64, *types.GoAuthError)
	// RevokeGrant disconnects one of the user's applications.
	RevokeGrant(ctx context.Context, userID, grantID string, metadata *types.RequestMetadata) *types.GoAuthError
	// RevokeUserGrants disconnects every application of a user. For hosts
	// that want an action of their own (closing an account, "sign out
	// everywhere") to end the access of connected applications too. It
	// returns how many were disconnected.
	RevokeUserGrants(ctx context.Context, userID string) (int64, *types.GoAuthError)

	AdminListClients(ctx context.Context, opts models.IDPClientListOpts) ([]dto.Client, int64, *types.GoAuthError)
	AdminCreateClient(ctx context.Context, actorID string, req *dto.ClientRequest) (*dto.Client, *types.GoAuthError)
	AdminGetClient(ctx context.Context, id string) (*dto.Client, *types.GoAuthError)
	AdminUpdateClient(ctx context.Context, actorID, id string, req *dto.ClientRequest) (*dto.Client, *types.GoAuthError)
	AdminDeleteClient(ctx context.Context, actorID, id string) *types.GoAuthError
	AdminRotateClientSecret(ctx context.Context, actorID, id string) (*dto.Client, *types.GoAuthError)

	// Seed creates or updates the clients declared in configuration.
	Seed(ctx context.Context) error
	// Cleanup deletes expired requests, codes and tokens.
	Cleanup(ctx context.Context)
}

// TokenRequest is a request to the token endpoint: the form body plus HTTP
// Basic client credentials.
type TokenRequest struct {
	Form        url.Values
	BasicID     string
	BasicSecret string
	HasBasic    bool
	Metadata    *types.RequestMetadata
}

// Stores are the repositories the service works on.
type Stores struct {
	Clients models.IDPClientRepository
	Grants  models.IDPGrantRepository
	Users   models.UserRepository
	Tokens  models.TokenRepository
}

// idpService implements IDPService.
type idpService struct {
	deps          config.ModuleDependencies
	settings      *Settings
	signer        *security.TokenSigner
	stores        Stores
	logger        types.Logger
	inTransaction bool
}

// NewIDPService creates the OpenID Connect provider service.
func NewIDPService(deps config.ModuleDependencies, settings *Settings, stores Stores) *idpService {
	return &idpService{
		deps:     deps,
		settings: settings,
		signer:   settings.Signer,
		stores:   stores,
		logger:   deps.Logger,
	}
}

func (s *idpService) now() time.Time {
	return time.Now().UTC()
}

// atomically runs fn with every repository bound to one transaction when the
// storage supports it, and rolls back when fn returns an error. Events
// emitted inside are delivered after commit. Do not use it for work that
// must persist when the request fails, such as ending a grant on replay.
func (s *idpService) atomically(ctx context.Context, fn func(tx *idpService) *types.GoAuthError) *types.GoAuthError {
	if s.inTransaction || s.deps.Storage == nil {
		return fn(s)
	}
	if _, ok := s.deps.Storage.(types.TransactionalStorage); !ok {
		return fn(s)
	}
	_, authErr := operation.Run(ctx, s.deps, func(deps config.ModuleDependencies) (struct{}, *types.GoAuthError) {
		tx := *s
		tx.deps = deps
		tx.inTransaction = true
		if store := deps.Storage.IDP(); store != nil {
			tx.stores.Clients, tx.stores.Grants = store.Clients(), store.Grants()
		}
		if core := deps.Storage.Core(); core != nil {
			tx.stores.Users, tx.stores.Tokens = core.Users(), core.Tokens()
		}
		return struct{}{}, fn(&tx)
	})
	return authErr
}

// emit publishes an event without failing the request when delivery fails.
func (s *idpService) emit(ctx context.Context, event types.EventType, data *types.IDPEventData) {
	if s.deps.Events == nil {
		return
	}
	if err := s.deps.Events.EmitAsync(ctx, event, data); err != nil {
		s.logger.Warnf("idp: failed to emit %s: %v", event, err)
	}
}

// Compile-time check: idpService implements IDPService.
var _ IDPService = (*idpService)(nil)
