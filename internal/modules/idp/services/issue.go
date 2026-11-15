package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// tokenData is the stored state behind an access token or a refresh token.
// It is fixed when the user approves and carried through every rotation.
type tokenData struct {
	GrantID  string   `json:"grant_id"`
	ClientID string   `json:"client_id"`
	UserID   string   `json:"user_id"`
	Scopes   []string `json:"scopes"`
	// AuthTime is when the user signed in, in Unix seconds; 0 when unknown.
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// Binding identifies the user's password as it was at approval.
	Binding string `json:"binding"`
}

// credentialBinding identifies the user's password as it is now without
// revealing anything about it: a digest of the stored hash, which already
// contains a random salt. A token records it at approval and stops working
// once it differs, that is when the password is changed, set or reset.
//
// The user's token version is deliberately not used for this. The stateless
// strategy increments it on every sign-out, and signing out of the host's
// application must not disconnect the applications the user signed in to.
func credentialBinding(user *models.User) string {
	sum := sha256.Sum256([]byte("goauth/idp/credential-binding/v1\x00" + user.PasswordHash))
	return hex.EncodeToString(sum[:16])
}

// tokenUser re-evaluates whether tokens may still be issued or honored for a
// user: the account must exist and be eligible, and its password unchanged
// since the user approved.
func (s *idpService) tokenUser(ctx context.Context, userID, binding string) (*models.User, *types.GoAuthError) {
	user, err := s.stores.Users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidGrant("")
		}
		return nil, errServer(err)
	}
	if security.CheckEligibility(user, s.deps.Config.Core) != nil {
		return nil, errInvalidGrant("")
	}
	if binding == "" || credentialBinding(user) != binding {
		return nil, errInvalidGrant("")
	}
	return user, nil
}

// refreshPolicy runs the authentication interceptors the way a session
// refresh does: a user who may no longer refresh a session of their own
// (organization membership ended, two-factor policy tightened) gets no new
// tokens for another application either. A challenge means the user would
// have to interact, which a token request cannot do, so it denies.
func (s *idpService) refreshPolicy(ctx context.Context, user *models.User, methods []string, metadata *types.RequestMetadata) *types.GoAuthError {
	if s.deps.AuthInterceptors == nil {
		return nil
	}
	_, challenges, _, err := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:           types.PhaseRefresh,
		User:            user,
		VerifiedMethods: methods,
		Metadata:        metadata,
		ExistingClaims:  map[string]interface{}{},
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errServer(err)
		}
		s.logger.Info("idp: token denied by authentication policy", "user_id", user.ID, "error", err.Error())
		return errInvalidGrant("")
	}
	if len(challenges) > 0 {
		return errInvalidGrant("")
	}
	return nil
}

// releasedClaims returns the claims about a user that scopes release to a
// client: the standard ones, and whatever the host's claims function adds.
func (s *idpService) releasedClaims(ctx context.Context, clientID string, user *models.User, scopes []string) (map[string]interface{}, *types.GoAuthError) {
	claims := userClaims(user, scopes)
	if s.settings.Claims == nil {
		return claims, nil
	}
	// The host gets copies: it must not change what is stored or issued.
	subject := *user
	extra, err := s.settings.Claims(ctx, config.IDPClaimsRequest{User: &subject, ClientID: clientID, Scopes: append([]string{}, scopes...)})
	if err != nil {
		s.logger.Errorf("idp: claims function failed for client %s: %v", clientID, err)
		return nil, errServer(err)
	}
	for name, value := range extra {
		if !reservedClaims[name] {
			claims[name] = value
		}
	}
	return claims, nil
}

// accessTokenHash is the at_hash claim: the left half of the SHA-256 digest
// of the access token (OpenID Connect Core section 3.1.3.6).
func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// issueInput describes the tokens to mint.
type issueInput struct {
	GrantType string
	// Scopes are the scopes of the access token and of the ID token claims.
	Scopes []string
	// GrantScopes are the scopes the refresh token carries: everything the
	// user approved for this sign-in, whatever a refresh narrowed Scopes to.
	GrantScopes []string
	// Nonce is copied into the ID token of a code redemption.
	Nonce    string
	AuthTime int64
	AMR      []string
	Binding  string
	// Previous is the refresh token being rotated, or nil for a code redemption.
	Previous *models.Token
}

// issue mints the tokens of one token response: an access token for the
// UserInfo endpoint, an ID token when the openid scope is granted, and a
// refresh token when the user approved offline_access.
func (s *idpService) issue(ctx context.Context, client *models.IDPClient, grant *models.IDPGrant, user *models.User, in issueInput) (*dto.TokenResponse, *types.GoAuthError) {
	now := s.now()
	record := func(tokenType, raw string, scopes []string, ttl time.Duration) (*models.Token, error) {
		data, err := json.Marshal(tokenData{
			GrantID: grant.ID, ClientID: client.ClientID, UserID: user.ID, Scopes: scopes,
			AuthTime: in.AuthTime, AMR: in.AMR, Binding: in.Binding,
		})
		if err != nil {
			return nil, err
		}
		// The record names no user: the grant does. Signing out clears the
		// user's own token records and must not take this one with them.
		return &models.Token{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Type:      tokenType,
			Token:     security.TokenDigest(raw),
			Data:      string(data),
			ExpiresAt: now.Add(ttl),
			CreatedAt: now,
		}, nil
	}

	accessToken, err := randomToken(32)
	if err != nil {
		return nil, errServer(err)
	}
	accessRecord, err := record(models.TokenTypeIDPAccess, accessToken, in.Scopes, s.settings.AccessTokenTTL)
	if err != nil {
		return nil, errServer(err)
	}
	response := &dto.TokenResponse{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: int64(s.settings.AccessTokenTTL / time.Second), Scope: oauthproto.JoinScope(in.Scopes),
	}

	if hasScope(in.Scopes, ScopeOpenID) {
		idToken, authErr := s.signIDToken(ctx, client, user, in, accessToken, now)
		if authErr != nil {
			return nil, authErr
		}
		response.IDToken = idToken
	}

	var refreshRecord *models.Token
	if hasScope(in.GrantScopes, ScopeOfflineAccess) {
		refreshToken, err := randomToken(32)
		if err != nil {
			return nil, errServer(err)
		}
		if refreshRecord, err = record(models.TokenTypeIDPRefresh, refreshToken, in.GrantScopes, s.settings.RefreshTokenTTL); err != nil {
			return nil, errServer(err)
		}
		response.RefreshToken = refreshToken
	}

	authErr := s.atomically(ctx, func(tx *idpService) *types.GoAuthError {
		if authErr := tx.storeRefreshToken(ctx, in.Previous, refreshRecord); authErr != nil {
			return authErr
		}
		if err := tx.stores.Tokens.Create(ctx, accessRecord); err != nil {
			return errServer(err)
		}
		return nil
	})
	if authErr != nil {
		return nil, authErr
	}
	if err := s.stores.Grants.TouchLastUsed(ctx, grant.ID, now); err != nil {
		s.logger.Warnf("idp: failed to record grant use: %v", err)
	}
	return response, nil
}

// storeRefreshToken persists a new refresh token. When it replaces previous,
// the replacement is committed only if previous was still unused, so two
// concurrent refreshes cannot both rotate the same token.
func (s *idpService) storeRefreshToken(ctx context.Context, previous, replacement *models.Token) *types.GoAuthError {
	switch {
	case previous == nil && replacement == nil:
		return nil
	case previous == nil:
		if err := s.stores.Tokens.Create(ctx, replacement); err != nil {
			return errServer(err)
		}
		return nil
	case replacement == nil:
		// Cannot happen: a refresh token exists only with offline_access.
		return errInvalidGrant("")
	}
	if rotator, ok := s.stores.Tokens.(models.TokenRotator); ok {
		if err := rotator.Rotate(ctx, previous, replacement); err != nil {
			if errors.Is(err, models.ErrConflict) {
				return errInvalidGrant("")
			}
			return errServer(err)
		}
		return nil
	}
	if err := s.stores.Tokens.MarkAsUsed(ctx, previous.ID); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return errInvalidGrant("")
		}
		return errServer(err)
	}
	if err := s.stores.Tokens.Create(ctx, replacement); err != nil {
		return errServer(err)
	}
	return nil
}

// signIDToken mints the ID token of a token response (OpenID Connect Core
// section 2).
func (s *idpService) signIDToken(ctx context.Context, client *models.IDPClient, user *models.User, in issueInput, accessToken string, now time.Time) (string, *types.GoAuthError) {
	claims, authErr := s.releasedClaims(ctx, client.ClientID, user, in.Scopes)
	if authErr != nil {
		return "", authErr
	}
	claims["iss"] = s.settings.Issuer
	claims["sub"] = user.ID
	claims["aud"] = client.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(s.settings.IDTokenTTL).Unix()
	claims["at_hash"] = accessTokenHash(accessToken)
	if in.AuthTime > 0 {
		claims["auth_time"] = in.AuthTime
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	if len(in.AMR) > 0 {
		claims["amr"] = in.AMR
	}
	token, err := s.signer.SignIDToken(claims)
	if err != nil {
		s.logger.Errorf("idp: failed to sign ID token for client %s: %v", client.ClientID, err)
		return "", errServer(err)
	}
	return token, nil
}
