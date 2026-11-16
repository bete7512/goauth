package gorm_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/invitation"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/passkeys"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// consoleContractStore migrates the tables of the modules whose storage the
// admin console relies on.
func consoleContractStore(t *testing.T) *store.GormStorage {
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
	a, err := auth.New(&config.Config{
		Storage: s, BorrowStorage: true,
		Security:  types.SecurityConfig{JwtSecretKey: "contract-test-secret-32-characters", EncryptionKey: "contract-test-encryption-secret"},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)
	for _, module := range []config.Component{admin.New(nil), organization.New(nil), invitation.New(nil), passkeys.New(&config.PasskeysModuleConfig{RPID: "localhost", RPOrigins: []string{"http://localhost"}})} {
		require.NoError(t, a.Use(module))
	}
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()); require.NoError(t, s.Close()) })
	return s
}

// Deleting an organization removes its memberships and invitations with it,
// and nothing of any other organization.
func TestOrganizationDeleteContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	orgs, members, invitations := s.Organization().Organizations(), s.Organization().Members(), s.Organization().Invitations()
	owner := uuid.NewString()
	create := func(name string) *models.Organization {
		org := &models.Organization{ID: uuid.NewString(), Name: name, Slug: name + "-" + uuid.NewString()[:8], OwnerID: owner, Active: true, CreatedAt: time.Now()}
		require.NoError(t, orgs.Create(ctx, org))
		require.NoError(t, members.Create(ctx, &models.OrganizationMember{OrgID: org.ID, UserID: owner, Role: "owner"}))
		require.NoError(t, members.Create(ctx, &models.OrganizationMember{OrgID: org.ID, UserID: uuid.NewString(), Role: "member"}))
		require.NoError(t, invitations.Create(ctx, &models.OrgInvitation{ID: uuid.NewString(), OrgID: org.ID, Email: uuid.NewString() + "@example.com", Role: "member", InviterID: owner, Token: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}))
		return org
	}
	doomed, kept := create("doomed"), create("kept")

	require.NoError(t, orgs.Delete(ctx, doomed.ID))
	_, err := orgs.FindByID(ctx, doomed.ID)
	require.ErrorIs(t, err, models.ErrNotFound)
	count, err := members.CountByOrg(ctx, doomed.ID)
	require.NoError(t, err)
	require.Zero(t, count, "memberships are deleted")
	opts := models.OrgInvitationListOpts{}
	opts.Normalize(100)
	list, _, err := invitations.ListByOrg(ctx, doomed.ID, opts)
	require.NoError(t, err)
	require.Empty(t, list, "invitations are deleted")

	count, err = members.CountByOrg(ctx, kept.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, count, "another organization is untouched")
	list, _, err = invitations.ListByOrg(ctx, kept.ID, opts)
	require.NoError(t, err)
	require.Len(t, list, 1)

	// Member listing works without an explicit sort field.
	memberOpts := models.MemberListOpts{}
	memberOpts.Normalize(100)
	rows, total, err := members.ListByOrg(ctx, kept.ID, memberOpts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, rows, 2)
}

// Administrators list every invitation, whoever sent it, with filters.
func TestInvitationListAllContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	repo := s.Invitation().Invitations()
	tag := uuid.NewString()[:8]
	for i, status := range []string{"pending", "pending", "accepted"} {
		require.NoError(t, repo.Create(ctx, &models.Invitation{
			ID: uuid.NewString(), Email: tag + "-" + status + "-" + uuid.NewString()[:4] + "@example.com", Purpose: map[bool]string{true: "beta", false: "platform"}[i == 0],
			InviterID: uuid.NewString(), Token: uuid.NewString(), Status: status, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}))
	}
	opts := models.InvitationListOpts{}
	opts.Normalize(100)
	all, total, err := repo.List(ctx, opts)
	require.NoError(t, err)
	require.EqualValues(t, 3, total, "invitations from three different inviters")
	require.Len(t, all, 3)

	opts = models.InvitationListOpts{Status: "pending"}
	opts.Normalize(100)
	_, total, err = repo.List(ctx, opts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)

	opts = models.InvitationListOpts{Purpose: "beta", ListingOpts: models.ListingOpts{Limit: 1}}
	opts.Normalize(100)
	page, total, err := repo.List(ctx, opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, page, 1)
}

// A passkey round-trips, including its authenticator model (AAGUID).
func TestPasskeyContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	repo := s.Passkeys().Passkeys()
	user := uuid.NewString()
	credential := &models.PasskeyCredential{ID: uuid.NewString(), UserID: user, CredentialID: []byte(uuid.NewString()), PublicKey: []byte("public-key"), AAGUID: []byte{1, 2, 3, 4}, Name: "YubiKey", CreatedAt: time.Now()}
	require.NoError(t, repo.Create(ctx, credential))
	found, err := repo.FindByID(ctx, credential.ID)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, 4}, found.AAGUID)
	require.Equal(t, "YubiKey", found.Name)
	list, err := repo.ListByUserID(ctx, user)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.NoError(t, repo.Delete(ctx, credential.ID))
	list, err = repo.ListByUserID(ctx, user)
	require.NoError(t, err)
	require.Empty(t, list)
}
