package services

import (
	"context"
	"errors"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// maxGrantListLimit caps one page of the grant listing.
const maxGrantListLimit = 100

// ListGrants lists the applications the user is connected to.
func (s *idpService) ListGrants(ctx context.Context, userID string, opts models.IDPGrantListOpts) ([]dto.Grant, int64, *types.GoAuthError) {
	opts.UserID = userID
	opts.Normalize(maxGrantListLimit)
	grants, total, err := s.stores.Grants.List(ctx, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list connected applications").Wrap(err)
	}
	clientIDs := make([]string, 0, len(grants))
	for _, grant := range grants {
		clientIDs = append(clientIDs, grant.ClientID)
	}
	clients, err := s.stores.Clients.FindByClientIDs(ctx, clientIDs)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to load client applications").Wrap(err)
	}
	byClientID := make(map[string]*models.IDPClient, len(clients))
	for _, client := range clients {
		byClientID[client.ClientID] = client
	}
	out := make([]dto.Grant, 0, len(grants))
	for _, grant := range grants {
		item := dto.Grant{
			ID: grant.ID, ClientID: grant.ClientID, ClientName: grant.ClientID,
			Scopes: append([]string{}, grant.Scopes...), CreatedAt: grant.CreatedAt, LastUsedAt: grant.LastUsedAt,
		}
		if client, ok := byClientID[grant.ClientID]; ok {
			item.ClientName, item.LogoURI, item.ClientURI = client.Name, client.LogoURI, client.ClientURI
		}
		out = append(out, item)
	}
	return out, total, nil
}

// RevokeGrant disconnects one of the user's applications: its tokens stop
// working and the user is asked to approve it again next time.
func (s *idpService) RevokeGrant(ctx context.Context, userID, grantID string, metadata *types.RequestMetadata) *types.GoAuthError {
	if grantID == "" {
		return types.NewIDPGrantNotFoundError()
	}
	grant, err := s.stores.Grants.FindByID(ctx, grantID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewIDPGrantNotFoundError()
		}
		return types.NewInternalError("failed to load connected application").Wrap(err)
	}
	// Another user's grant is answered like one that does not exist.
	if grant.UserID != userID {
		return types.NewIDPGrantNotFoundError()
	}
	if err := s.stores.Grants.Delete(ctx, grant.ID); err != nil {
		return types.NewInternalError("failed to disconnect application").Wrap(err)
	}
	event := &types.IDPEventData{
		UserID: userID, ActorID: userID, ClientID: grant.ClientID, GrantID: grant.ID, Reason: grantEndedByUser,
		TargetID: grant.ID, TargetType: "idp_grant", Details: "Client application " + grant.ClientID + " disconnected by the user",
	}
	if metadata != nil {
		event.IP, event.UserAgent = metadata.IPAddress, metadata.UserAgent
	}
	s.emit(ctx, types.EventIDPGrantRevoked, event)
	return nil
}

// Cleanup deletes token records past their expiry: pending requests,
// authorization codes, access tokens and refresh tokens. A rotated refresh
// token is kept until then, which is what lets a replay be recognized.
func (s *idpService) Cleanup(ctx context.Context) {
	if _, err := s.stores.Tokens.DeleteExpired(ctx); err != nil {
		s.logger.Warnf("idp: cleanup of expired tokens failed: %v", err)
	}
}

// RevokeUserGrants disconnects every application of a user and returns how
// many were disconnected.
func (s *idpService) RevokeUserGrants(ctx context.Context, userID string) (int64, *types.GoAuthError) {
	if userID == "" {
		return 0, nil
	}
	count, err := s.stores.Grants.DeleteByUser(ctx, userID)
	if err != nil {
		return 0, types.NewInternalError("failed to disconnect applications").Wrap(err)
	}
	if count > 0 {
		s.emit(ctx, types.EventIDPGrantRevoked, &types.IDPEventData{
			UserID: userID, Reason: grantEndedByHost, TargetID: userID, TargetType: "user",
			Details: "Every client application of the user was disconnected",
		})
	}
	return count, nil
}
