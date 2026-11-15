package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// maxAccessTokenLength bounds what is looked up as an access token.
const maxAccessTokenLength = 256

// UserInfo returns the claims an access token releases (OpenID Connect Core
// section 5.3). The token is honored only while its grant exists, its client
// is enabled and its user may still sign in with the password they had when
// they approved.
func (s *idpService) UserInfo(ctx context.Context, accessToken string) (map[string]interface{}, *types.GoAuthError) {
	if accessToken == "" || len(accessToken) > maxAccessTokenLength {
		return nil, errInvalidToken()
	}
	record, err := s.stores.Tokens.FindByToken(ctx, security.TokenDigest(accessToken))
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidToken()
		}
		return nil, errServer(err)
	}
	var data tokenData
	if record.Type != models.TokenTypeIDPAccess || expired(record.ExpiresAt, s.now()) ||
		json.Unmarshal([]byte(record.Data), &data) != nil || data.GrantID == "" {
		return nil, errInvalidToken()
	}
	if _, err := s.stores.Grants.FindByID(ctx, data.GrantID); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidToken()
		}
		return nil, errServer(err)
	}
	if _, authErr := s.resolveClient(ctx, data.ClientID); authErr != nil {
		if authErr.Code == CodeInvalidClient {
			return nil, errInvalidToken()
		}
		return nil, authErr
	}
	user, authErr := s.tokenUser(ctx, data.UserID, data.Binding)
	if authErr != nil {
		if authErr.Code == CodeInvalidGrant {
			return nil, errInvalidToken()
		}
		return nil, authErr
	}
	if !hasScope(data.Scopes, ScopeOpenID) {
		return nil, oauthError(CodeInsufficientScope, http.StatusForbidden, "The access token does not carry the openid scope")
	}
	claims, authErr := s.releasedClaims(ctx, data.ClientID, user, data.Scopes)
	if authErr != nil {
		return nil, authErr
	}
	claims["sub"] = user.ID
	return claims, nil
}
