package gorm_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// idpContractStore is contractStore with the identity provider module
// registered, so that its migrations create the tables under test.
func idpContractStore(t *testing.T) *store.GormStorage {
	t.Helper()
	dialect, dsn := types.DialectType(os.Getenv("GOAUTH_CONTRACT_DIALECT")), os.Getenv("GOAUTH_CONTRACT_DSN")
	connections := 16
	if dialect == "" {
		dialect = types.DialectTypeSqlite
		dsn = "file:" + uuid.NewString() + "?mode=memory&cache=shared&_busy_timeout=5000"
		connections = 1
	}
	s, err := store.NewStorage(store.Config{Dialect: dialect, DSN: dsn, LogLevel: "silent", MaxOpenConns: connections, MaxIdleConns: connections})
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	a, err := auth.New(&config.Config{
		Storage: s, BorrowStorage: true, APIURL: "https://api.example.com",
		Security:       types.SecurityConfig{JwtSecretKey: "contract-test-secret-32-characters", EncryptionKey: "contract-test-encryption-secret"},
		FrontendConfig: &config.FrontendConfig{URL: "https://app.example.com"},
		Migration:      config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)
	require.NoError(t, a.Use(idp.New(&config.IDPModuleConfig{
		SigningKey:      config.IDPSigningKey{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})},
		CleanupInterval: -1,
	})))
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()); require.NoError(t, s.Close()) })
	return s
}

func idpClientRecord() *models.IDPClient {
	id := uuid.NewString()
	return &models.IDPClient{
		ClientID: "app-" + id, Name: "Dashboard " + id, SecretHash: "s1:digest",
		RedirectURIs: models.StringList{"https://dashboard.example.com/callback", "http://127.0.0.1/cb"},
		Scopes:       models.StringList{"openid", "email"}, RequirePKCE: true, SkipConsent: true, Managed: true,
		LogoURI: "https://dashboard.example.com/logo.png",
	}
}

func TestIDPClientContracts(t *testing.T) {
	s := idpContractStore(t)
	ctx := context.Background()
	repo := s.IDP().Clients()

	client := idpClientRecord()
	require.NoError(t, repo.Create(ctx, client))
	require.NotEmpty(t, client.ID, "the repository assigns an ID")

	found, err := repo.FindByClientID(ctx, client.ClientID)
	require.NoError(t, err)
	require.Equal(t, client.ID, found.ID)
	require.Equal(t, client.RedirectURIs, found.RedirectURIs, "lists survive the round trip")
	require.Equal(t, client.Scopes, found.Scopes)
	require.True(t, found.RequirePKCE)
	require.True(t, found.SkipConsent)
	require.True(t, found.Managed)
	require.False(t, found.Public)
	require.Nil(t, found.LastUsedAt)
	require.False(t, found.CreatedAt.IsZero())

	byID, err := repo.FindByID(ctx, client.ID)
	require.NoError(t, err)
	require.Equal(t, client.ClientID, byID.ClientID)

	t.Run("client_id is case-sensitive", func(t *testing.T) {
		_, err := repo.FindByClientID(ctx, strings.ToUpper(client.ClientID))
		require.ErrorIs(t, err, models.ErrNotFound)
	})
	t.Run("unknown records", func(t *testing.T) {
		_, err := repo.FindByClientID(ctx, "nobody-"+uuid.NewString())
		require.ErrorIs(t, err, models.ErrNotFound)
		_, err = repo.FindByID(ctx, uuid.NewString())
		require.ErrorIs(t, err, models.ErrNotFound)
		require.ErrorIs(t, repo.Update(ctx, &models.IDPClient{ID: uuid.NewString(), ClientID: "x-" + uuid.NewString()}), models.ErrNotFound)
	})
	t.Run("a taken client_id conflicts", func(t *testing.T) {
		duplicate := idpClientRecord()
		duplicate.ClientID = client.ClientID
		require.ErrorIs(t, repo.Create(ctx, duplicate), models.ErrConflict)
	})
	t.Run("a conflict leaves the surrounding transaction usable", func(t *testing.T) {
		other := idpClientRecord()
		err := s.WithTransaction(ctx, func(tx types.Storage) error {
			duplicate := idpClientRecord()
			duplicate.ClientID = client.ClientID
			if err := tx.IDP().Clients().Create(ctx, duplicate); !errors.Is(err, models.ErrConflict) {
				t.Errorf("expected a conflict, got %v", err)
			}
			return tx.IDP().Clients().Create(ctx, other)
		})
		require.NoError(t, err)
		_, err = repo.FindByClientID(ctx, other.ClientID)
		require.NoError(t, err, "work after the conflict was committed")
	})
	t.Run("update saves every field, false and empty included", func(t *testing.T) {
		found.Name = "Renamed"
		found.RequirePKCE, found.SkipConsent, found.Managed, found.Disabled = false, false, false, true
		found.SecretHash, found.LogoURI = "", ""
		found.Public = true
		found.RedirectURIs = models.StringList{"https://dashboard.example.com/v2"}
		require.NoError(t, repo.Update(ctx, found))
		updated, err := repo.FindByID(ctx, client.ID)
		require.NoError(t, err)
		require.Equal(t, "Renamed", updated.Name)
		require.False(t, updated.RequirePKCE)
		require.False(t, updated.SkipConsent)
		require.False(t, updated.Managed)
		require.True(t, updated.Disabled)
		require.True(t, updated.Public)
		require.Empty(t, updated.SecretHash)
		require.Empty(t, updated.LogoURI)
		require.Equal(t, models.StringList{"https://dashboard.example.com/v2"}, updated.RedirectURIs)
		require.Equal(t, client.ClientID, updated.ClientID)
		require.WithinDuration(t, found.CreatedAt, updated.CreatedAt, time.Second, "created_at is kept")
	})
	t.Run("last use", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, repo.TouchLastUsed(ctx, client.ID, at))
		touched, err := repo.FindByID(ctx, client.ID)
		require.NoError(t, err)
		require.NotNil(t, touched.LastUsedAt)
		require.WithinDuration(t, at, *touched.LastUsedAt, time.Second)
	})
	t.Run("listing", func(t *testing.T) {
		marker := "zq" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
		managed, unmanaged := idpClientRecord(), idpClientRecord()
		managed.Name, unmanaged.Name = "Alpha "+marker, "Beta "+marker
		unmanaged.Managed = false
		require.NoError(t, repo.Create(ctx, managed))
		require.NoError(t, repo.Create(ctx, unmanaged))

		opts := models.IDPClientListOpts{Query: strings.ToUpper(marker)}
		opts.SortField, opts.SortDir = "name", "asc"
		opts.Normalize(100)
		clients, total, err := repo.List(ctx, opts)
		require.NoError(t, err)
		require.EqualValues(t, 2, total, "the search ignores case")
		require.Len(t, clients, 2)
		require.Equal(t, managed.ClientID, clients[0].ClientID, "sorted by name")

		only := true
		opts.Managed = &only
		clients, total, err = repo.List(ctx, opts)
		require.NoError(t, err)
		require.EqualValues(t, 1, total)
		require.Equal(t, managed.ClientID, clients[0].ClientID)

		opts.Managed, opts.Limit = nil, 1
		clients, total, err = repo.List(ctx, opts)
		require.NoError(t, err)
		require.EqualValues(t, 2, total, "the total ignores the page size")
		require.Len(t, clients, 1)

		// A wildcard in the search matches itself, not everything.
		wild := models.IDPClientListOpts{Query: "%" + marker + "_"}
		wild.Normalize(100)
		_, total, err = repo.List(ctx, wild)
		require.NoError(t, err)
		require.Zero(t, total)

		several, err := repo.FindByClientIDs(ctx, []string{managed.ClientID, unmanaged.ClientID, "nobody-" + marker})
		require.NoError(t, err)
		require.Len(t, several, 2)
		none, err := repo.FindByClientIDs(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, none)
	})
	t.Run("delete", func(t *testing.T) {
		require.NoError(t, repo.Delete(ctx, client.ID))
		_, err := repo.FindByID(ctx, client.ID)
		require.ErrorIs(t, err, models.ErrNotFound)
		require.NoError(t, repo.Delete(ctx, client.ID), "deleting what is gone is not an error")
	})
}

func TestIDPGrantContracts(t *testing.T) {
	s := idpContractStore(t)
	ctx := context.Background()
	repo := s.IDP().Grants()
	userID, clientID := uuid.NewString(), "app-"+uuid.NewString()

	grant := &models.IDPGrant{UserID: userID, ClientID: clientID, Scopes: models.StringList{"openid", "email"}}
	require.NoError(t, repo.Create(ctx, grant))
	require.NotEmpty(t, grant.ID)

	found, err := repo.FindByUserAndClient(ctx, userID, clientID)
	require.NoError(t, err)
	require.Equal(t, grant.ID, found.ID)
	require.Equal(t, models.StringList{"openid", "email"}, found.Scopes)
	require.Nil(t, found.LastUsedAt)

	t.Run("one grant per user and client", func(t *testing.T) {
		require.ErrorIs(t, repo.Create(ctx, &models.IDPGrant{UserID: userID, ClientID: clientID, Scopes: models.StringList{"openid"}}), models.ErrConflict)
		// The same user with another client, and the same client with
		// another user, are different grants.
		require.NoError(t, repo.Create(ctx, &models.IDPGrant{UserID: userID, ClientID: "other-" + uuid.NewString()}))
		require.NoError(t, repo.Create(ctx, &models.IDPGrant{UserID: uuid.NewString(), ClientID: clientID}))
	})
	t.Run("concurrent approvals create one grant", func(t *testing.T) {
		user, client := uuid.NewString(), "app-"+uuid.NewString()
		runContenders(t, func(int) error {
			return repo.Create(ctx, &models.IDPGrant{UserID: user, ClientID: client, Scopes: models.StringList{"openid"}})
		})
		grants, total, err := repo.List(ctx, models.IDPGrantListOpts{ListingOpts: models.DefaultListingOpts(), UserID: user})
		require.NoError(t, err)
		require.EqualValues(t, 1, total)
		require.Len(t, grants, 1)
	})
	t.Run("client_id is case-sensitive", func(t *testing.T) {
		_, err := repo.FindByUserAndClient(ctx, userID, strings.ToUpper(clientID))
		require.ErrorIs(t, err, models.ErrNotFound)
	})
	t.Run("update saves the scopes", func(t *testing.T) {
		found.Scopes = append(found.Scopes, "profile")
		require.NoError(t, repo.Update(ctx, found))
		updated, err := repo.FindByID(ctx, grant.ID)
		require.NoError(t, err)
		require.Equal(t, models.StringList{"openid", "email", "profile"}, updated.Scopes)
		require.Equal(t, userID, updated.UserID)
		require.ErrorIs(t, repo.Update(ctx, &models.IDPGrant{ID: uuid.NewString(), Scopes: models.StringList{"openid"}}), models.ErrNotFound)
	})
	t.Run("last use", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, repo.TouchLastUsed(ctx, grant.ID, at))
		touched, err := repo.FindByID(ctx, grant.ID)
		require.NoError(t, err)
		require.NotNil(t, touched.LastUsedAt)
		require.WithinDuration(t, at, *touched.LastUsedAt, time.Second)
	})
	t.Run("listing by user and client", func(t *testing.T) {
		opts := models.IDPGrantListOpts{UserID: userID}
		opts.Normalize(100)
		grants, total, err := repo.List(ctx, opts)
		require.NoError(t, err)
		require.EqualValues(t, 2, total)
		require.Len(t, grants, 2)
		opts.ClientID = clientID
		grants, total, err = repo.List(ctx, opts)
		require.NoError(t, err)
		require.EqualValues(t, 1, total)
		require.Equal(t, grant.ID, grants[0].ID)
	})
	t.Run("delete", func(t *testing.T) {
		removed, err := repo.DeleteByClient(ctx, clientID)
		require.NoError(t, err)
		require.EqualValues(t, 2, removed, "both users' grants for the client")
		_, err = repo.FindByID(ctx, grant.ID)
		require.ErrorIs(t, err, models.ErrNotFound)

		removed, err = repo.DeleteByUser(ctx, userID)
		require.NoError(t, err)
		require.EqualValues(t, 1, removed, "the user's grant for the other client")

		single := &models.IDPGrant{UserID: userID, ClientID: clientID}
		require.NoError(t, repo.Create(ctx, single), "a deleted grant can be given again")
		require.NoError(t, repo.Delete(ctx, single.ID))
		_, err = repo.FindByUserAndClient(ctx, userID, clientID)
		require.ErrorIs(t, err, models.ErrNotFound)
	})
}

// A grant and the token records written with it commit or roll back together.
func TestIDPGrantRollsBackWithItsTransaction(t *testing.T) {
	s := idpContractStore(t)
	ctx := context.Background()
	userID, clientID := uuid.NewString(), "app-"+uuid.NewString()
	failure := errors.New("abort")

	err := s.WithTransaction(ctx, func(tx types.Storage) error {
		if err := tx.IDP().Grants().Create(ctx, &models.IDPGrant{UserID: userID, ClientID: clientID}); err != nil {
			return err
		}
		if err := tx.Core().Tokens().Create(ctx, &models.Token{ID: uuid.NewString(), Type: models.TokenTypeIDPCode, Token: "s1:" + uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now()}); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	_, err = s.IDP().Grants().FindByUserAndClient(ctx, userID, clientID)
	require.ErrorIs(t, err, models.ErrNotFound, "the grant was rolled back")
}
