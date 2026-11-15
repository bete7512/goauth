package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
)

// Seed makes the stored clients match the ones declared in configuration: it
// creates the missing ones and rewrites the existing ones. A client that was
// declared before and no longer is gets disabled and handed over to the admin
// API, where it can be deleted or enabled again.
func (s *idpService) Seed(ctx context.Context) error {
	declared := make(map[string]bool, len(s.settings.SeedClients))
	for i := range s.settings.SeedClients {
		cfg := &s.settings.SeedClients[i]
		declared[cfg.ClientID] = true
		if err := s.seedClient(ctx, cfg); err != nil {
			return err
		}
	}
	return s.releaseUndeclared(ctx, declared)
}

func (s *idpService) seedClient(ctx context.Context, cfg *config.IDPClientConfig) error {
	in := &clientInput{
		Name: cfg.Name, RedirectURIs: cfg.RedirectURIs, Scopes: cfg.Scopes, Public: cfg.Public,
		RequirePKCE: !cfg.AllowWithoutPKCE, SkipConsent: cfg.SkipConsent,
		LogoURI: cfg.LogoURI, ClientURI: cfg.ClientURI, Disabled: cfg.Disabled,
	}
	if err := in.normalize(); err != nil {
		return fmt.Errorf("idp: Clients[%s]: %w", cfg.ClientID, err)
	}
	secretHash := ""
	if !cfg.Public {
		secretHash = clientSecretDigest(cfg.Secret)
	}

	existing, err := s.stores.Clients.FindByClientID(ctx, cfg.ClientID)
	switch {
	case errors.Is(err, models.ErrNotFound):
		now := s.now()
		client := &models.IDPClient{
			ID: uuid.Must(uuid.NewV7()).String(), ClientID: cfg.ClientID, SecretHash: secretHash,
			Managed: true, CreatedAt: now, UpdatedAt: now,
		}
		in.apply(client)
		if err := s.stores.Clients.Create(ctx, client); err != nil {
			return fmt.Errorf("idp: Clients[%s]: failed to store: %w", cfg.ClientID, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("idp: Clients[%s]: failed to load: %w", cfg.ClientID, err)
	case !existing.Managed:
		// Taking over a row an administrator created would silently
		// replace its secret and redirect URIs.
		return fmt.Errorf("idp: Clients[%s]: a client application with this client_id was registered through the admin API; delete it there or choose another ClientID", cfg.ClientID)
	}
	in.apply(existing)
	existing.SecretHash = secretHash
	if err := s.stores.Clients.Update(ctx, existing); err != nil {
		return fmt.Errorf("idp: Clients[%s]: failed to store: %w", cfg.ClientID, err)
	}
	return nil
}

// releaseUndeclared disables the managed clients that configuration no
// longer declares and makes them editable through the admin API.
func (s *idpService) releaseUndeclared(ctx context.Context, declared map[string]bool) error {
	managed := true
	opts := models.IDPClientListOpts{Managed: &managed}
	opts.Limit = maxClientListLimit
	opts.SortField, opts.SortDir = "created_at", "asc"
	var orphans []*models.IDPClient
	for {
		clients, _, err := s.stores.Clients.List(ctx, opts)
		if err != nil {
			return fmt.Errorf("idp: failed to list configured client applications: %w", err)
		}
		for _, client := range clients {
			if !declared[client.ClientID] {
				orphans = append(orphans, client)
			}
		}
		if len(clients) < opts.Limit {
			break
		}
		opts.Offset += len(clients)
	}
	for _, client := range orphans {
		client.Managed, client.Disabled = false, true
		if err := s.stores.Clients.Update(ctx, client); err != nil {
			return fmt.Errorf("idp: failed to disable client application %q removed from configuration: %w", client.ClientID, err)
		}
		s.logger.Warnf("idp: client application %q is no longer declared in configuration and was disabled", client.ClientID)
	}
	return nil
}
