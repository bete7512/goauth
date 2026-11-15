package gorm_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// rbacContractStore is contractStore with the rbac module registered, so
// that its migrations create the tables under test.
func rbacContractStore(t *testing.T) *store.GormStorage {
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
	require.NoError(t, a.Use(rbac.New(nil)))
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()); require.NoError(t, s.Close()) })
	return s
}

func TestRBACRoleContracts(t *testing.T) {
	s := rbacContractStore(t)
	ctx := context.Background()
	repo := s.RBAC().Roles()
	org, otherOrg := uuid.NewString(), uuid.NewString()

	billing := &models.Role{OrgID: org, Key: "billing", Name: "Billing", Description: "Invoices", Grants: models.StringList{"invoice:*", "report:read"}, CreatedBy: uuid.NewString()}
	require.NoError(t, repo.Create(ctx, billing))
	require.NotEmpty(t, billing.ID)
	require.False(t, billing.CreatedAt.IsZero())

	// One role per key in an organization; the same key elsewhere is a
	// different role, and so is the application-wide one.
	err := repo.Create(ctx, &models.Role{OrgID: org, Key: "billing", Name: "Again"})
	require.ErrorIs(t, err, models.ErrConflict)
	require.NoError(t, repo.Create(ctx, &models.Role{OrgID: otherOrg, Key: "billing", Name: "Theirs"}))
	global := &models.Role{Key: "billing-" + uuid.NewString()[:8], Name: "Global"}
	require.NoError(t, repo.Create(ctx, global))

	// Keys are case-sensitive on every dialect.
	require.NoError(t, repo.Create(ctx, &models.Role{OrgID: org, Key: "BILLING", Name: "Shouting"}))
	found, err := repo.FindByKey(ctx, org, "billing")
	require.NoError(t, err)
	require.Equal(t, billing.ID, found.ID)
	require.Equal(t, "Billing", found.Name)
	require.Equal(t, "Invoices", found.Description)
	require.Equal(t, models.StringList{"invoice:*", "report:read"}, found.Grants)
	require.Equal(t, billing.CreatedBy, found.CreatedBy)

	_, err = repo.FindByKey(ctx, org, "missing")
	require.ErrorIs(t, err, models.ErrNotFound)
	_, err = repo.FindByKey(ctx, "", "billing")
	require.ErrorIs(t, err, models.ErrNotFound, "an organization's role is not an application-wide one")

	// A role without grants reads back as an empty list.
	empty := &models.Role{OrgID: org, Key: "empty", Name: "Empty"}
	require.NoError(t, repo.Create(ctx, empty))
	found, err = repo.FindByKey(ctx, org, "empty")
	require.NoError(t, err)
	require.Empty(t, found.Grants)

	several, err := repo.FindByKeys(ctx, org, []string{"billing", "empty", "missing"})
	require.NoError(t, err)
	require.Len(t, several, 2)
	none, err := repo.FindByKeys(ctx, org, nil)
	require.NoError(t, err)
	require.Empty(t, none)

	listed, err := repo.ListByOrg(ctx, org)
	require.NoError(t, err)
	require.Len(t, listed, 3)
	require.Equal(t, "billing", listed[0].Key, "oldest first")
	count, err := repo.CountByOrg(ctx, org)
	require.NoError(t, err)
	require.EqualValues(t, 3, count)
	count, err = repo.CountByOrg(ctx, uuid.NewString())
	require.NoError(t, err)
	require.Zero(t, count)

	// Update changes what a role is called and grants, never where it lives.
	billing.Name, billing.Description, billing.Grants = "Billing team", "", models.StringList{"invoice:read"}
	billing.Key, billing.OrgID = "renamed", otherOrg
	require.NoError(t, repo.Update(ctx, billing))
	found, err = repo.FindByKey(ctx, org, "billing")
	require.NoError(t, err)
	require.Equal(t, "Billing team", found.Name)
	require.Empty(t, found.Description)
	require.Equal(t, models.StringList{"invoice:read"}, found.Grants)
	require.NotNil(t, found.UpdatedAt)
	_, err = repo.FindByKey(ctx, otherOrg, "renamed")
	require.ErrorIs(t, err, models.ErrNotFound)
	require.ErrorIs(t, repo.Update(ctx, &models.Role{ID: uuid.NewString(), Name: "Ghost"}), models.ErrNotFound)

	require.NoError(t, repo.Delete(ctx, empty.ID))
	_, err = repo.FindByKey(ctx, org, "empty")
	require.ErrorIs(t, err, models.ErrNotFound)
	require.NoError(t, repo.Delete(ctx, uuid.NewString()), "deleting a role that is gone is not an error")

	require.NoError(t, repo.DeleteByOrg(ctx, org))
	count, err = repo.CountByOrg(ctx, org)
	require.NoError(t, err)
	require.Zero(t, count)
	_, err = repo.FindByKey(ctx, otherOrg, "billing")
	require.NoError(t, err, "another organization's roles are untouched")
	_, err = repo.FindByKey(ctx, "", global.Key)
	require.NoError(t, err)
}

func TestRBACAssignmentContracts(t *testing.T) {
	s := rbacContractStore(t)
	ctx := context.Background()
	repo := s.RBAC().Assignments()
	user, other := uuid.NewString(), uuid.NewString()
	org, otherOrg := uuid.NewString(), uuid.NewString()
	membership, actor := uuid.NewString(), uuid.NewString()
	globalRef := models.RoleScopeRef{Type: models.RoleScopeGlobal}
	orgRef := models.RoleScopeRef{Type: models.RoleScopeOrg, ID: org}
	assign := func(userID, scopeType, scopeID, role string) {
		t.Helper()
		row := &models.RoleAssignment{UserID: userID, ScopeType: scopeType, ScopeID: scopeID, RoleKey: role, GrantedBy: actor}
		if scopeType == models.RoleScopeOrg {
			row.MembershipID = membership
		}
		require.NoError(t, repo.Create(ctx, row))
		require.NotEmpty(t, row.ID)
		require.False(t, row.CreatedAt.IsZero())
	}

	assign(user, models.RoleScopeGlobal, "", "viewer")
	assign(user, models.RoleScopeOrg, org, "billing")
	assign(user, models.RoleScopeOrg, org, "auditor")
	assign(user, models.RoleScopeOrg, otherOrg, "billing")
	assign(other, models.RoleScopeOrg, org, "billing")

	// A user holds a role once per scope.
	err := repo.Create(ctx, &models.RoleAssignment{UserID: user, ScopeType: models.RoleScopeOrg, ScopeID: org, RoleKey: "billing"})
	require.ErrorIs(t, err, models.ErrConflict)

	keys := func(rows []*models.RoleAssignment) []string {
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.ScopeType+"/"+row.RoleKey)
		}
		return out
	}

	// The lookup behind every check: this user, these scopes, nothing else.
	rows, err := repo.ListByUser(ctx, user, []models.RoleScopeRef{globalRef, orgRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"global/viewer", "org/billing", "org/auditor"}, keys(rows))
	for _, row := range rows {
		require.Equal(t, user, row.UserID)
		require.Equal(t, actor, row.GrantedBy)
		if row.ScopeType == models.RoleScopeOrg {
			require.Equal(t, org, row.ScopeID)
			require.Equal(t, membership, row.MembershipID)
		} else {
			require.Empty(t, row.ScopeID)
			require.Empty(t, row.MembershipID)
		}
	}
	rows, err = repo.ListByUser(ctx, user, []models.RoleScopeRef{globalRef})
	require.NoError(t, err)
	require.Equal(t, []string{"global/viewer"}, keys(rows))
	rows, err = repo.ListByUser(ctx, user, nil)
	require.NoError(t, err)
	require.Empty(t, rows, "no scopes: no rows, not every row")
	rows, err = repo.ListByUser(ctx, uuid.NewString(), []models.RoleScopeRef{globalRef, orgRef})
	require.NoError(t, err)
	require.Empty(t, rows)

	// Listing a scope: filters, total and paging.
	opts := models.RoleAssignmentListOpts{}
	opts.Normalize(100)
	rows, total, err := repo.ListByScope(ctx, models.RoleScopeOrg, org, opts)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, rows, 3)

	opts = models.RoleAssignmentListOpts{RoleKey: "billing"}
	opts.Normalize(100)
	rows, total, err = repo.ListByScope(ctx, models.RoleScopeOrg, org, opts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, rows, 2)

	opts = models.RoleAssignmentListOpts{UserID: user, ListingOpts: models.ListingOpts{Limit: 1, SortField: "role_key", SortDir: "asc"}}
	opts.Normalize(100)
	rows, total, err = repo.ListByScope(ctx, models.RoleScopeOrg, org, opts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total, "the total ignores the page size")
	require.Equal(t, []string{"org/auditor"}, keys(rows))
	opts.Offset = 1
	rows, _, err = repo.ListByScope(ctx, models.RoleScopeOrg, org, opts)
	require.NoError(t, err)
	require.Equal(t, []string{"org/billing"}, keys(rows))

	// Removing one role from one user in one scope.
	require.NoError(t, repo.Delete(ctx, user, models.RoleScopeOrg, org, "auditor"))
	require.NoError(t, repo.Delete(ctx, user, models.RoleScopeOrg, org, "auditor"), "deleting twice is not an error")
	rows, err = repo.ListByUser(ctx, user, []models.RoleScopeRef{orgRef})
	require.NoError(t, err)
	require.Equal(t, []string{"org/billing"}, keys(rows))

	// Removing a role from everyone in a scope leaves other scopes alone.
	require.NoError(t, repo.DeleteByRole(ctx, models.RoleScopeOrg, org, "billing"))
	_, total, err = repo.ListByScope(ctx, models.RoleScopeOrg, org, models.RoleAssignmentListOpts{ListingOpts: models.DefaultListingOpts()})
	require.NoError(t, err)
	require.Zero(t, total)
	rows, err = repo.ListByUser(ctx, user, []models.RoleScopeRef{{Type: models.RoleScopeOrg, ID: otherOrg}})
	require.NoError(t, err)
	require.Len(t, rows, 1)

	assign(user, models.RoleScopeOrg, org, "billing")
	assign(other, models.RoleScopeOrg, org, "billing")
	require.NoError(t, repo.DeleteByUserAndScope(ctx, user, models.RoleScopeOrg, org))
	rows, err = repo.ListByUser(ctx, user, []models.RoleScopeRef{globalRef, orgRef, {Type: models.RoleScopeOrg, ID: otherOrg}})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"global/viewer", "org/billing"}, keys(rows), "only that organization's assignments went")

	require.NoError(t, repo.DeleteByScope(ctx, models.RoleScopeOrg, org))
	rows, err = repo.ListByUser(ctx, other, []models.RoleScopeRef{orgRef})
	require.NoError(t, err)
	require.Empty(t, rows)

	require.NoError(t, repo.DeleteByUser(ctx, user))
	rows, err = repo.ListByUser(ctx, user, []models.RoleScopeRef{globalRef, {Type: models.RoleScopeOrg, ID: otherOrg}})
	require.NoError(t, err)
	require.Empty(t, rows)
}

// Two requests that give the same role to the same user at once must leave
// one row, and the loser must be told it was a duplicate, not a failure.
func TestRBACAssignmentIsCreatedOnceUnderContention(t *testing.T) {
	s := rbacContractStore(t)
	ctx := context.Background()
	repo := s.RBAC().Assignments()
	user := uuid.NewString()

	var created, conflicts atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := repo.Create(ctx, &models.RoleAssignment{UserID: user, ScopeType: models.RoleScopeGlobal, RoleKey: "viewer"})
			switch {
			case err == nil:
				created.Add(1)
			case errors.Is(err, models.ErrConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	group.Wait()
	require.EqualValues(t, 1, created.Load())
	require.EqualValues(t, 15, conflicts.Load())
	rows, err := repo.ListByUser(ctx, user, []models.RoleScopeRef{{Type: models.RoleScopeGlobal}})
	require.NoError(t, err)
	require.Len(t, rows, 1)
}

func TestRBACTransactionContracts(t *testing.T) {
	s := rbacContractStore(t)
	ctx := context.Background()
	org, user := uuid.NewString(), uuid.NewString()
	role := &models.Role{OrgID: org, Key: "billing", Name: "Billing"}
	require.NoError(t, s.RBAC().Roles().Create(ctx, role))
	require.NoError(t, s.RBAC().Assignments().Create(ctx, &models.RoleAssignment{UserID: user, ScopeType: models.RoleScopeOrg, ScopeID: org, RoleKey: "billing"}))
	orgRef := []models.RoleScopeRef{{Type: models.RoleScopeOrg, ID: org}}

	// A role and its assignments go together or not at all.
	failure := errors.New("stop")
	err := s.RBAC().WithTransaction(ctx, func(tx types.RBACStorage) error {
		if err := tx.Assignments().DeleteByRole(ctx, models.RoleScopeOrg, org, "billing"); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
	rows, err := s.RBAC().Assignments().ListByUser(ctx, user, orgRef)
	require.NoError(t, err)
	require.Len(t, rows, 1, "the delete was rolled back")

	require.NoError(t, s.RBAC().WithTransaction(ctx, func(tx types.RBACStorage) error {
		if err := tx.Assignments().DeleteByRole(ctx, models.RoleScopeOrg, org, "billing"); err != nil {
			return err
		}
		return tx.Roles().Delete(ctx, role.ID)
	}))
	rows, err = s.RBAC().Assignments().ListByUser(ctx, user, orgRef)
	require.NoError(t, err)
	require.Empty(t, rows)
	_, err = s.RBAC().Roles().FindByKey(ctx, org, "billing")
	require.ErrorIs(t, err, models.ErrNotFound)
}
