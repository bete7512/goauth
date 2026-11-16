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
	"github.com/bete7512/goauth/pkg/modules/team"
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
	for _, module := range []config.Component{admin.New(nil), organization.New(nil), team.New(nil), invitation.New(nil), passkeys.New(&config.PasskeysModuleConfig{RPID: "localhost", RPOrigins: []string{"http://localhost"}})} {
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

// A ban's columns survive a round trip, and lifting it clears them.
func TestUserBanContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	users := s.Core().Users()
	user := &models.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Username: uuid.NewString(), PasswordHash: "x", Active: true, CreatedAt: time.Now()}
	require.NoError(t, users.Create(ctx, user))

	fresh, err := users.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.Nil(t, fresh.BannedAt)
	require.False(t, fresh.Banned(time.Now()))

	at, until := time.Now().UTC().Truncate(time.Second), time.Now().Add(24*time.Hour).UTC().Truncate(time.Second)
	fresh.BannedAt, fresh.BannedUntil, fresh.BanReason = &at, &until, "Spam — reported twice"
	require.NoError(t, users.Update(ctx, fresh))
	banned, err := users.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, banned.BannedAt)
	require.NotNil(t, banned.BannedUntil)
	require.True(t, banned.BannedAt.Equal(at))
	require.True(t, banned.BannedUntil.Equal(until))
	require.Equal(t, "Spam — reported twice", banned.BanReason)
	require.True(t, banned.Banned(time.Now()))
	require.False(t, banned.Banned(until.Add(time.Second)), "an ended ban no longer counts")

	banned.BannedAt, banned.BannedUntil, banned.BanReason = nil, nil, ""
	require.NoError(t, users.Update(ctx, banned))
	lifted, err := users.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.Nil(t, lifted.BannedAt)
	require.Nil(t, lifted.BannedUntil)
	require.Empty(t, lifted.BanReason)
}

// Teams: a sub-tree is a prefix of the path, a move rewrites everything
// beneath, delete refuses a team with children, and an organization's teams
// go with it.
func TestTeamContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	teams, members := s.Team().Teams(), s.Team().Members()
	org, otherOrg := uuid.NewString(), uuid.NewString()
	create := func(orgID, name string, parent *models.Team) *models.Team {
		team := &models.Team{ID: uuid.NewString(), OrgID: orgID, Name: name, Slug: name}
		parentPath := ""
		if parent != nil {
			team.ParentID, team.Depth, parentPath = parent.ID, parent.Depth+1, parent.Path
		}
		team.Path = models.TeamPath(parentPath, team.ID)
		require.NoError(t, teams.Create(ctx, team))
		return team
	}
	eng := create(org, "eng", nil)
	backend := create(org, "backend", eng)
	db := create(org, "db", backend)
	design := create(org, "design", nil)
	elsewhere := create(otherOrg, "eng", nil)

	dup := &models.Team{ID: uuid.NewString(), OrgID: org, Name: "eng", Slug: "eng", Path: "/x/"}
	require.ErrorIs(t, teams.Create(ctx, dup), models.ErrConflict)

	subtree, err := teams.Subtree(ctx, org, eng.Path)
	require.NoError(t, err)
	require.Len(t, subtree, 3)
	require.Equal(t, eng.ID, subtree[0].ID)

	found, err := teams.FindByIDs(ctx, []string{db.ID, elsewhere.ID, uuid.NewString()})
	require.NoError(t, err)
	require.Len(t, found, 2)

	top, total, err := teams.List(ctx, org, models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: 10, SortField: "name", SortDir: "asc"}, Top: true})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Equal(t, "design", top[0].Slug)

	// Move backend (with db) beneath design.
	oldPath := backend.Path
	backend.ParentID, backend.Depth, backend.Path = design.ID, 1, models.TeamPath(design.Path, backend.ID)
	require.NoError(t, teams.Move(ctx, backend, oldPath))
	movedDB, err := teams.FindByID(ctx, db.ID)
	require.NoError(t, err)
	require.Equal(t, design.Path+backend.ID+"/"+db.ID+"/", movedDB.Path)
	require.Equal(t, 2, movedDB.Depth)
	// A stale move is refused.
	require.ErrorIs(t, teams.Move(ctx, backend, oldPath), models.ErrConflict)

	count, err := teams.CountChildren(ctx, design.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)

	user := uuid.NewString()
	require.NoError(t, members.Create(ctx, &models.TeamMember{TeamID: db.ID, OrgID: org, UserID: user, Role: models.TeamRoleLead, MembershipID: "m1"}))
	require.ErrorIs(t, members.Create(ctx, &models.TeamMember{TeamID: db.ID, OrgID: org, UserID: user}), models.ErrConflict)
	rows, err := members.ListByTeams(ctx, user, movedDB.AncestorIDs())
	require.NoError(t, err)
	require.Len(t, rows, 1)

	require.ErrorIs(t, teams.Delete(ctx, backend.ID), models.ErrConflict, "a team with teams beneath it stays")
	require.NoError(t, teams.Delete(ctx, db.ID))
	rows, err = members.ListByUser(ctx, org, user)
	require.NoError(t, err)
	require.Empty(t, rows, "memberships go with the team")

	require.NoError(t, teams.DeleteByOrg(ctx, org))
	left, _, err := teams.List(ctx, org, models.TeamListOpts{ListingOpts: models.ListingOpts{Limit: 10}})
	require.NoError(t, err)
	require.Empty(t, left)
	_, err = teams.FindByID(ctx, elsewhere.ID)
	require.NoError(t, err, "other organizations keep their teams")
}

// Per-day counts group by UTC day in every dialect.
func TestDailyCountContracts(t *testing.T) {
	s := consoleContractStore(t)
	ctx := context.Background()
	users := s.Core().Users()
	today := time.Now().UTC().Truncate(24 * time.Hour)
	counter, ok := users.(models.UserSignupCounter)
	require.True(t, ok)
	// Other contract tests share the database, so counts are compared with
	// what was there before.
	count := func() map[string]int64 {
		rows, err := counter.CountCreatedPerDay(ctx, today.AddDate(0, 0, -29))
		require.NoError(t, err)
		got := map[string]int64{}
		for _, row := range rows {
			got[row.Day] = row.Count
		}
		return got
	}
	before := count()
	old := today.AddDate(0, 0, -40)
	for i, at := range []time.Time{today.Add(time.Hour), today.Add(23 * time.Hour), today.Add(-time.Hour), old} {
		user := &models.User{ID: uuid.NewString(), Email: uuid.NewString() + "@example.com", Username: uuid.NewString(), PasswordHash: "x", Active: true, CreatedAt: at}
		require.NoError(t, users.Create(ctx, user), i)
	}
	after := count()
	day, yesterday := today.Format("2006-01-02"), today.AddDate(0, 0, -1).Format("2006-01-02")
	require.Equal(t, before[day]+2, after[day], "%v", after)
	require.Equal(t, before[yesterday]+1, after[yesterday], "%v", after)
	_, counted := after[old.Format("2006-01-02")]
	require.False(t, counted, "the day 40 days ago is outside the window")
}
