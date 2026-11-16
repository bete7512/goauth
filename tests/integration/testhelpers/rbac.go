//go:build integration

package testhelpers

import (
	"context"
	"net/http"
	"testing"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/team"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// RBACEnv is an auth instance with the rbac module, plus the mux the auth
// routes are registered on so that a test can add guarded routes of its own.
type RBACEnv struct {
	Auth  *auth.Auth
	Authz *rbac.Module
	Mux   *http.ServeMux
	Store types.Storage
}

// SetupRBAC creates a stateless auth instance with the rbac and admin
// modules. The organization module is registered when cfg.Organizations is set.
func SetupRBAC(t *testing.T, cfg *rbac.Config) *RBACEnv {
	t.Helper()
	store := newStore(t)
	authInstance, err := auth.New(&config.Config{
		Storage:   store,
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("rbac-test-secret-key-32charlongx", "rbac-test-encryption-key-32char!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		RateLimit: &config.RateLimitModuleConfig{Disabled: true},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	authz := rbac.New(cfg)
	require.NoError(t, authInstance.Use(authz))
	require.NoError(t, authInstance.Use(admin.New(nil)))
	if cfg != nil && cfg.Organizations {
		require.NoError(t, authInstance.Use(organization.New(nil)))
	}
	if cfg != nil && cfg.Teams {
		require.NoError(t, authInstance.Use(team.New(nil)))
	}

	require.NoError(t, authInstance.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, authInstance.Close()) })
	mux := http.NewServeMux()
	stdhttp.Register(mux, authInstance)
	return &RBACEnv{Auth: authInstance, Authz: authz, Mux: mux, Store: store}
}

// OK is a handler that answers 200, for routes a test guards.
var OK = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

// SignupUser creates a user and returns the user's ID and an access token.
func SignupUser(t *testing.T, handler http.Handler, email string) (userID, token string) {
	t.Helper()
	token, _ = SignupAndLogin(t, handler, email, "Test1234", "Test User")
	userID, _ = Me(t, handler, token)["id"].(string)
	require.NotEmpty(t, userID)
	return userID, token
}

// MakeSuperAdmin sets the super admin flag on a user.
func MakeSuperAdmin(t *testing.T, store types.Storage, userID string) {
	t.Helper()
	ctx := context.Background()
	user, err := store.Core().Users().FindByID(ctx, userID)
	require.NoError(t, err)
	user.IsSuperAdmin = true
	require.NoError(t, store.Core().Users().Update(ctx, user))
}

// CreateOrg creates an organization owned by the caller and returns its ID.
func CreateOrg(t *testing.T, handler http.Handler, token, name string) string {
	t.Helper()
	w := JSONPost(handler, "/auth/org", map[string]interface{}{"name": name}, AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code, "create org: %s", w.Body.String())
	return ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)
}

// AddOrgMember adds a user to an organization directly in storage, skipping
// the invitation flow, and returns the membership ID.
func AddOrgMember(t *testing.T, store types.Storage, orgID, userID string, role types.OrgRole) string {
	t.Helper()
	member := &models.OrganizationMember{ID: uuid.NewString(), OrgID: orgID, UserID: userID, Role: string(role)}
	require.NoError(t, store.Organization().Members().Create(context.Background(), member))
	return member.ID
}

// SwitchOrg signs the caller in to an organization and returns the new
// access token.
func SwitchOrg(t *testing.T, handler http.Handler, token, orgID string) string {
	t.Helper()
	w := JSONPost(handler, "/auth/org/switch", map[string]interface{}{"org_id": orgID}, AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "switch org: %s", w.Body.String())
	switched, _ := ParseJSON(t, w.Body)["data"].(map[string]interface{})["access_token"].(string)
	require.NotEmpty(t, switched)
	return switched
}

// ErrorCode returns the error code of an API error response body.
func ErrorCode(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	data, _ := body["data"].(map[string]interface{})
	code, _ := data["code"].(string)
	return code
}
