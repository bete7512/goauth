package services

import (
	"context"
	"errors"
	"strings"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// maxClientListLimit caps one page of the client listing.
const maxClientListLimit = 100

func inputFromRequest(req *dto.ClientRequest) *clientInput {
	in := &clientInput{
		Name: req.Name, RedirectURIs: req.RedirectURIs, Scopes: req.Scopes, Public: req.Public,
		RequirePKCE: true, SkipConsent: req.SkipConsent, LogoURI: req.LogoURI, ClientURI: req.ClientURI, Disabled: req.Disabled,
	}
	if req.RequirePKCE != nil {
		in.RequirePKCE = *req.RequirePKCE
	}
	return in
}

// loadClient finds a client by its internal ID for an administrator.
func (s *idpService) loadClient(ctx context.Context, id string) (*models.IDPClient, *types.GoAuthError) {
	if id == "" {
		return nil, types.NewIDPClientNotFoundError()
	}
	client, err := s.stores.Clients.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewIDPClientNotFoundError()
		}
		return nil, types.NewInternalError("failed to load client application").Wrap(err)
	}
	return client, nil
}

func (s *idpService) clientEvent(actorID string, client *models.IDPClient, details string) *types.IDPEventData {
	return &types.IDPEventData{
		ActorID: actorID, ClientID: client.ClientID, ClientName: client.Name,
		TargetID: client.ID, TargetType: "idp_client", Details: details,
	}
}

// AdminListClients lists the registered client applications.
func (s *idpService) AdminListClients(ctx context.Context, opts models.IDPClientListOpts) ([]dto.Client, int64, *types.GoAuthError) {
	opts.Normalize(maxClientListLimit)
	clients, total, err := s.stores.Clients.List(ctx, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list client applications").Wrap(err)
	}
	out := make([]dto.Client, 0, len(clients))
	for _, client := range clients {
		out = append(out, clientDTO(client))
	}
	return out, total, nil
}

// AdminCreateClient registers a client application. The response is the only
// place its secret is ever shown.
func (s *idpService) AdminCreateClient(ctx context.Context, actorID string, req *dto.ClientRequest) (*dto.Client, *types.GoAuthError) {
	in := inputFromRequest(req)
	if err := in.normalize(); err != nil {
		return nil, types.NewIDPInvalidClientError(err.Error())
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = uuid.Must(uuid.NewV7()).String()
	} else if !validClientID(clientID) {
		return nil, types.NewIDPInvalidClientError("client_id must be 3 to 128 characters of letters, digits, '.', '_', '~' or '-'")
	}

	now := s.now()
	client := &models.IDPClient{ID: uuid.Must(uuid.NewV7()).String(), ClientID: clientID, CreatedAt: now, UpdatedAt: now}
	in.apply(client)
	secret := ""
	if !client.Public {
		var err error
		if secret, err = randomToken(32); err != nil {
			return nil, types.NewInternalError("failed to generate client secret").Wrap(err)
		}
		client.SecretHash = clientSecretDigest(secret)
	}
	if err := s.stores.Clients.Create(ctx, client); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return nil, types.NewIDPClientExistsError()
		}
		return nil, types.NewInternalError("failed to store client application").Wrap(err)
	}
	s.emit(ctx, types.EventIDPClientCreated, s.clientEvent(actorID, client, "Client application "+client.Name+" registered"))
	out := clientDTO(client)
	out.ClientSecret = secret
	return &out, nil
}

// AdminGetClient returns one client application.
func (s *idpService) AdminGetClient(ctx context.Context, id string) (*dto.Client, *types.GoAuthError) {
	client, authErr := s.loadClient(ctx, id)
	if authErr != nil {
		return nil, authErr
	}
	out := clientDTO(client)
	return &out, nil
}

// AdminUpdateClient replaces the registration of a client application. Its
// client_id never changes. A client that stops being public gets a secret,
// returned once; one that becomes public loses its secret.
func (s *idpService) AdminUpdateClient(ctx context.Context, actorID, id string, req *dto.ClientRequest) (*dto.Client, *types.GoAuthError) {
	client, authErr := s.loadClient(ctx, id)
	if authErr != nil {
		return nil, authErr
	}
	if client.Managed {
		return nil, types.NewIDPClientManagedError()
	}
	in := inputFromRequest(req)
	if err := in.normalize(); err != nil {
		return nil, types.NewIDPInvalidClientError(err.Error())
	}
	wasPublic := client.Public
	in.apply(client)
	secret := ""
	switch {
	case client.Public:
		client.SecretHash = ""
	case wasPublic:
		var err error
		if secret, err = randomToken(32); err != nil {
			return nil, types.NewInternalError("failed to generate client secret").Wrap(err)
		}
		client.SecretHash = clientSecretDigest(secret)
	}
	if err := s.stores.Clients.Update(ctx, client); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewIDPClientNotFoundError()
		}
		return nil, types.NewInternalError("failed to store client application").Wrap(err)
	}
	s.emit(ctx, types.EventIDPClientUpdated, s.clientEvent(actorID, client, "Client application "+client.Name+" updated"))
	out := clientDTO(client)
	out.ClientSecret = secret
	return &out, nil
}

// AdminDeleteClient removes a client application and disconnects every user
// from it.
func (s *idpService) AdminDeleteClient(ctx context.Context, actorID, id string) *types.GoAuthError {
	client, authErr := s.loadClient(ctx, id)
	if authErr != nil {
		return authErr
	}
	if client.Managed {
		return types.NewIDPClientManagedError()
	}
	return s.atomically(ctx, func(tx *idpService) *types.GoAuthError {
		// Tokens name their grant: without it they stop working.
		if _, err := tx.stores.Grants.DeleteByClient(ctx, client.ClientID); err != nil {
			return types.NewInternalError("failed to remove the client application's grants").Wrap(err)
		}
		if err := tx.stores.Clients.Delete(ctx, client.ID); err != nil {
			return types.NewInternalError("failed to delete client application").Wrap(err)
		}
		tx.emit(ctx, types.EventIDPClientDeleted, tx.clientEvent(actorID, client, "Client application "+client.Name+" deleted"))
		return nil
	})
}

// AdminRotateClientSecret replaces the secret of a confidential client. The
// old secret stops working at once.
func (s *idpService) AdminRotateClientSecret(ctx context.Context, actorID, id string) (*dto.Client, *types.GoAuthError) {
	client, authErr := s.loadClient(ctx, id)
	if authErr != nil {
		return nil, authErr
	}
	if client.Managed {
		return nil, types.NewIDPClientManagedError()
	}
	if client.Public {
		return nil, types.NewIDPInvalidClientError("A public client has no secret")
	}
	secret, err := randomToken(32)
	if err != nil {
		return nil, types.NewInternalError("failed to generate client secret").Wrap(err)
	}
	client.SecretHash = clientSecretDigest(secret)
	if err := s.stores.Clients.Update(ctx, client); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewIDPClientNotFoundError()
		}
		return nil, types.NewInternalError("failed to store client secret").Wrap(err)
	}
	s.emit(ctx, types.EventIDPClientSecretRotated, s.clientEvent(actorID, client, "Secret of client application "+client.Name+" rotated"))
	out := clientDTO(client)
	out.ClientSecret = secret
	return &out, nil
}
