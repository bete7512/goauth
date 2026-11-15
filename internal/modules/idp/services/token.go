package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// The grant types of the token endpoint.
const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
)

// Reasons a grant is ended.
const (
	grantEndedByUser    = "user"
	grantEndedByHost    = "host"
	grantEndedCodeReuse = "authorization_code_reuse"
	grantEndedReuse     = "refresh_token_reuse"
)

// Token serves the token endpoint (RFC 6749 section 3.2, OpenID Connect Core
// section 3.1.3).
func (s *idpService) Token(ctx context.Context, req *TokenRequest) (*dto.TokenResponse, *types.GoAuthError) {
	for name, values := range req.Form {
		if len(values) > 1 {
			return nil, errInvalidRequest(name + " must not be repeated")
		}
	}
	grantType := req.Form.Get("grant_type")
	if grantType == "" {
		return nil, errInvalidRequest("grant_type is required")
	}
	if grantType != grantTypeAuthorizationCode && grantType != grantTypeRefreshToken {
		return nil, oauthError(CodeUnsupportedGrantType, http.StatusBadRequest, "Unsupported grant_type")
	}
	client, authErr := s.authenticateClient(ctx, req)
	if authErr != nil {
		return nil, authErr
	}

	var response *dto.TokenResponse
	event := types.IDPEventData{ClientID: client.ClientID, ClientName: client.Name, GrantType: grantType}
	switch grantType {
	case grantTypeAuthorizationCode:
		response, authErr = s.exchangeCode(ctx, client, req, &event)
	case grantTypeRefreshToken:
		response, authErr = s.refresh(ctx, client, req, &event)
	}
	if authErr != nil {
		return nil, authErr
	}
	s.touchClient(ctx, client)
	if req.Metadata != nil {
		event.IP, event.UserAgent = req.Metadata.IPAddress, req.Metadata.UserAgent
	}
	s.emit(ctx, types.EventIDPTokenIssued, &event)
	return response, nil
}

// exchangeCode redeems an authorization code (RFC 6749 section 4.1.3 with PKCE).
func (s *idpService) exchangeCode(ctx context.Context, client *models.IDPClient, req *TokenRequest, event *types.IDPEventData) (*dto.TokenResponse, *types.GoAuthError) {
	code := req.Form.Get("code")
	if code == "" {
		return nil, errInvalidRequest("code is required")
	}
	record, err := s.stores.Tokens.FindByToken(ctx, security.TokenDigest(code))
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidGrant("")
		}
		return nil, errServer(err)
	}
	var data authorizationCode
	if record.Type != models.TokenTypeIDPCode || json.Unmarshal([]byte(record.Data), &data) != nil || data.GrantID == "" {
		return nil, errInvalidGrant("")
	}
	now := s.now()
	// A code means something only to the client it was issued to. Anyone
	// else presenting it learns nothing and changes nothing: not the code,
	// and not the grant behind it.
	if data.ClientID != client.ClientID {
		return nil, errInvalidGrant("")
	}
	if expired(record.ExpiresAt, now) {
		return nil, errInvalidGrant("")
	}
	if record.Used {
		// A code presented twice while it is valid means it leaked: end
		// whatever the first redemption produced.
		s.endGrant(ctx, data.GrantID, grantEndedCodeReuse, client, req.Metadata)
		return nil, errInvalidGrant("")
	}
	// Consume before validating, so a failed attempt also burns the code.
	if err := s.stores.Tokens.MarkAsUsed(ctx, record.ID); err != nil {
		if errors.Is(err, models.ErrConflict) {
			s.endGrant(ctx, data.GrantID, grantEndedCodeReuse, client, req.Metadata)
			return nil, errInvalidGrant("")
		}
		return nil, errServer(err)
	}
	presented := req.Form.Get("redirect_uri")
	switch {
	case presented != "" && presented != data.RedirectURI:
		return nil, errInvalidGrant("redirect_uri does not match the authorization request")
	case presented == "" && data.CodeChallenge == "":
		// Without PKCE the redirect URI is what ties the code to the
		// request that produced it (OpenID Connect Core section 3.1.3.2).
		return nil, errInvalidGrant("redirect_uri is required")
	}
	verifier := req.Form.Get("code_verifier")
	switch {
	case data.CodeChallenge != "":
		if !oauthproto.VerifyPKCE(verifier, data.CodeChallenge) {
			return nil, errInvalidGrant("PKCE verification failed")
		}
	case verifier != "":
		// A verifier for a request that had no challenge points at a
		// downgraded authorization request (RFC 9700 section 4.8.2).
		return nil, errInvalidGrant("PKCE verification failed")
	}

	grant, authErr := s.liveGrant(ctx, data.GrantID)
	if authErr != nil {
		return nil, authErr
	}
	user, authErr := s.tokenUser(ctx, data.UserID, data.Binding)
	if authErr != nil {
		return nil, authErr
	}
	event.UserID, event.Scopes, event.GrantID = user.ID, data.Scopes, grant.ID
	return s.issue(ctx, client, grant, user, issueInput{
		GrantType: grantTypeAuthorizationCode, Scopes: data.Scopes, GrantScopes: data.Scopes,
		Nonce: data.Nonce, AuthTime: data.AuthTime, AMR: data.AMR, Binding: data.Binding,
	})
}

// refresh redeems a refresh token (RFC 6749 section 6) and rotates it. A
// rotated token that shows up again outside the leeway ends the grant.
func (s *idpService) refresh(ctx context.Context, client *models.IDPClient, req *TokenRequest, event *types.IDPEventData) (*dto.TokenResponse, *types.GoAuthError) {
	raw := req.Form.Get("refresh_token")
	if raw == "" {
		return nil, errInvalidRequest("refresh_token is required")
	}
	record, err := s.stores.Tokens.FindByToken(ctx, security.TokenDigest(raw))
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidGrant("")
		}
		return nil, errServer(err)
	}
	var data tokenData
	if record.Type != models.TokenTypeIDPRefresh || json.Unmarshal([]byte(record.Data), &data) != nil || data.GrantID == "" {
		return nil, errInvalidGrant("")
	}
	if data.ClientID != client.ClientID {
		return nil, errInvalidGrant("")
	}
	now := s.now()
	if record.Used {
		// Inside the leeway this is a retry or a second request racing the
		// first: it gets an error and nothing else happens. Outside it the
		// token was copied, and the grant ends.
		if !s.withinLeeway(record, now) {
			s.reuseDetected(ctx, data.GrantID, client, req.Metadata)
		}
		return nil, errInvalidGrant("")
	}
	if expired(record.ExpiresAt, now) {
		return nil, errInvalidGrant("")
	}
	grant, authErr := s.liveGrant(ctx, data.GrantID)
	if authErr != nil {
		return nil, authErr
	}

	scopes := data.Scopes
	if requested, err := oauthproto.ParseScope(req.Form.Get("scope")); err != nil {
		return nil, errInvalidScope("The scope parameter is malformed")
	} else if len(requested) > 0 {
		if !oauthproto.ScopeSubset(requested, data.Scopes) {
			return nil, errInvalidScope("A refresh cannot add scopes to the original grant")
		}
		scopes = requested
	}

	user, authErr := s.tokenUser(ctx, data.UserID, data.Binding)
	if authErr != nil {
		return nil, authErr
	}
	if authErr := s.refreshPolicy(ctx, user, data.AMR, req.Metadata); authErr != nil {
		return nil, authErr
	}
	event.UserID, event.Scopes, event.GrantID = user.ID, scopes, grant.ID
	return s.issue(ctx, client, grant, user, issueInput{
		GrantType: grantTypeRefreshToken, Scopes: scopes, GrantScopes: data.Scopes,
		AuthTime: data.AuthTime, AMR: data.AMR, Binding: data.Binding, Previous: record,
	})
}

// withinLeeway reports whether a used refresh token was used so recently
// that presenting it again is treated as a retry rather than a replay.
func (s *idpService) withinLeeway(record *models.Token, now time.Time) bool {
	return s.settings.RefreshReuseLeeway > 0 && record.UsedAt != nil && now.Sub(*record.UsedAt) <= s.settings.RefreshReuseLeeway
}

// liveGrant loads the grant a code or token names. A grant that is gone was
// revoked, and everything issued from it with it.
func (s *idpService) liveGrant(ctx context.Context, id string) (*models.IDPGrant, *types.GoAuthError) {
	grant, err := s.stores.Grants.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidGrant("")
		}
		return nil, errServer(err)
	}
	return grant, nil
}

// reuseDetected ends the grant of a replayed refresh token and reports it.
func (s *idpService) reuseDetected(ctx context.Context, grantID string, client *models.IDPClient, metadata *types.RequestMetadata) {
	grant := s.endGrant(ctx, grantID, grantEndedReuse, client, metadata)
	if grant == nil {
		return
	}
	event := &types.IDPEventData{
		UserID: grant.UserID, ClientID: client.ClientID, ClientName: client.Name, GrantID: grant.ID,
		Reason: grantEndedReuse, TargetID: grant.ID, TargetType: "idp_grant",
		Details: "A rotated refresh token was presented again; the application was disconnected",
	}
	if metadata != nil {
		event.IP, event.UserAgent = metadata.IPAddress, metadata.UserAgent
	}
	s.emit(ctx, types.EventIDPTokenReuseDetected, event)
	s.logger.Warn("idp: refresh token reuse detected, grant ended", "grant_id", grant.ID, "client_id", client.ClientID, "user_id", grant.UserID)
}

// endGrant deletes a grant, which ends every token issued from it, and
// reports it. It returns the grant, or nil when there was none to end.
func (s *idpService) endGrant(ctx context.Context, grantID, reason string, client *models.IDPClient, metadata *types.RequestMetadata) *models.IDPGrant {
	grant, err := s.stores.Grants.FindByID(ctx, grantID)
	if err != nil {
		return nil
	}
	if err := s.stores.Grants.Delete(ctx, grant.ID); err != nil {
		s.logger.Errorf("idp: failed to end grant %s: %v", grant.ID, err)
		return nil
	}
	event := &types.IDPEventData{
		UserID: grant.UserID, ClientID: grant.ClientID, GrantID: grant.ID, Reason: reason,
		TargetID: grant.ID, TargetType: "idp_grant", Details: "Client application " + grant.ClientID + " disconnected (" + reason + ")",
	}
	if client != nil {
		event.ClientName = client.Name
	}
	if metadata != nil {
		event.IP, event.UserAgent = metadata.IPAddress, metadata.UserAgent
	}
	s.emit(ctx, types.EventIDPGrantRevoked, event)
	return grant
}
