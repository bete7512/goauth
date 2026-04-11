//go:build integration

// Package testhelpers provides shared test infrastructure for integration tests.
// All setup factories, HTTP helpers, and reusable actions live here.
package testhelpers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/csrf"
	"github.com/bete7512/goauth/pkg/modules/magiclink"
	"github.com/bete7512/goauth/pkg/modules/notification"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/invitation"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
	"github.com/stretchr/testify/require"
)

// defaultSecurityConfig returns a base SecurityConfig for tests.
func defaultSecurityConfig(jwtKey, encKey string) types.SecurityConfig {
	return types.SecurityConfig{
		JwtSecretKey:  jwtKey,
		EncryptionKey: encKey,
		Session: types.SessionConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			SessionTTL:      30 * 24 * time.Hour,
		},
		PasswordPolicy: types.PasswordPolicy{
			MinLength: 4,
			MaxLength: 128,
		},
	}
}

// storeCounter ensures each test gets a unique SQLite database.
var storeCounter int

// newStore creates an isolated in-memory SQLite storage for each test.
func newStore(t *testing.T) types.Storage {
	t.Helper()
	storeCounter++
	dsn := fmt.Sprintf("file:test_%s_%d?mode=memory&cache=shared&_fk=1", t.Name(), storeCounter)
	store, err := storage.NewGormStorage(storage.GormConfig{
		Dialect:  types.DialectTypeSqlite,
		DSN:      dsn,
		LogLevel: "silent",
	})
	require.NoError(t, err)
	return store
}

// initAuth creates an Auth instance, initializes it, and returns an HTTP handler.
func initAuth(t *testing.T, authInstance *auth.Auth) http.Handler {
	t.Helper()
	err := authInstance.Initialize(context.Background())
	require.NoError(t, err)
	mux := http.NewServeMux()
	return stdhttp.Register(mux, authInstance)
}

// SetupStatelessAuth creates a stateless JWT auth instance with default config.
func SetupStatelessAuth(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("integration-test-secret-key-32ch", "integration-test-encryption-key!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)
	return authInstance, initAuth(t, authInstance)
}

// SetupSessionAuth creates a session-based auth instance.
func SetupSessionAuth(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("e2e-session-test-secret-key-32ch", "e2e-session-test-encryption-key!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	err = authInstance.Use(session.New(&config.SessionModuleConfig{
		EnableSessionManagement: true,
	}, nil))
	require.NoError(t, err)

	return authInstance, initAuth(t, authInstance)
}

// SetupAuthWithLockout creates an auth instance with account lockout enabled.
func SetupAuthWithLockout(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	sec := defaultSecurityConfig("security-test-secret-key-32chars", "security-test-encryption-key-32!")
	sec.PasswordPolicy.MinLength = 8
	sec.PasswordPolicy.RequireUppercase = true
	sec.Lockout = types.LockoutConfig{
		Enabled:         true,
		MaxAttempts:     3,
		LockoutDuration: 1 * time.Minute,
	}

	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  sec,
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)
	return authInstance, initAuth(t, authInstance)
}

// SetupFullAuth creates a session auth instance with admin + audit + csrf modules.
func SetupFullAuth(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("full-auth-test-secret-key-32char", "full-auth-test-encryption-key32!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(session.New(&config.SessionModuleConfig{EnableSessionManagement: true}, nil)))
	require.NoError(t, authInstance.Use(admin.New(nil)))
	require.NoError(t, authInstance.Use(audit.New(nil)))
	require.NoError(t, authInstance.Use(csrf.New(nil)))

	return authInstance, initAuth(t, authInstance)
}

// SetupStatelessWithAdmin creates a stateless auth instance with admin + audit modules.
func SetupStatelessWithAdmin(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("admin-test-secret-key-32charlong", "admin-test-encryption-key-32ch!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(admin.New(nil)))
	require.NoError(t, authInstance.Use(audit.New(nil)))

	return authInstance, initAuth(t, authInstance)
}

// SetupStatelessWithOrg creates a stateless auth instance with organization module.
func SetupStatelessWithOrg(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("org-test-secret-key-32charlongxx", "org-test-encryption-key-32char!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(organization.New(nil)))

	return authInstance, initAuth(t, authInstance)
}

// SetupStatelessWithInvitation creates a stateless auth instance with standalone invitation module.
func SetupStatelessWithInvitation(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("inv-test-secret-key-32charslongx", "inv-test-encryption-key-32char!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(invitation.New(nil)))

	return authInstance, initAuth(t, authInstance)
}

// SetupStatelessWithTwoFactor creates a stateless auth instance with 2FA module.
func SetupStatelessWithTwoFactor(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		Security:  defaultSecurityConfig("2fa-test-secret-key-32charslongx", "2fa-test-encryption-key-32chars!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(twofactor.New()))

	return authInstance, initAuth(t, authInstance)
}

// SetupStatelessWithMagicLink creates a stateless auth with magic link + notification (email sink).
// Returns the email sink so tests can extract tokens/codes from captured emails.
func SetupStatelessWithMagicLink(t *testing.T) (*auth.Auth, http.Handler, *EmailSink) {
	t.Helper()
	sink := NewEmailSink()

	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		APIURL:    "http://localhost:8080",
		Security:  defaultSecurityConfig("ml-test-secret-key-32charslongxx", "ml-test-encryption-key-32chars!!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(notification.New(&notification.Config{
		EmailSender:          sink,
		EnableMagicLinkEmail: true,
	})))
	require.NoError(t, authInstance.Use(magiclink.New(&config.MagicLinkModuleConfig{
		TokenExpiry:  15 * time.Minute,
		AutoRegister: true,
	}, nil)))

	return authInstance, initAuth(t, authInstance), sink
}

// SetupStatelessWithNotification creates a stateless auth with notification module (email sink).
// Returns the email sink so tests can extract verification tokens, reset codes, etc.
func SetupStatelessWithNotification(t *testing.T) (*auth.Auth, http.Handler, *EmailSink) {
	t.Helper()
	sink := NewEmailSink()

	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		APIURL:    "http://localhost:8080",
		Security:  defaultSecurityConfig("notif-test-secret-key-32charlong", "notif-test-encryption-key-32ch!"),
		Core:      &config.CoreConfig{RequireEmailVerification: true},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(notification.New(&notification.Config{
		EmailSender:              sink,
		EnableWelcomeEmail:       true,
		EnablePasswordResetEmail: true,
	})))

	return authInstance, initAuth(t, authInstance), sink
}

// SetupStatelessWithOAuth creates a stateless auth instance with OAuth module.
// Provider credentials come from env vars. If not set, providers are registered
// but tests should use the fake OAuth server to override URLs.
//
// Env vars (for real provider testing in CI):
//
//	GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET
//	GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET
func SetupStatelessWithOAuth(t *testing.T) (*auth.Auth, http.Handler) {
	t.Helper()

	providerConfigs := make(map[string]*config.OAuthProviderConfig)

	// Google — from env or test placeholder
	googleID := os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	googleSecret := os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
	if googleID == "" {
		googleID = "test-google-client-id"
		googleSecret = "test-google-client-secret"
	}
	providerConfigs["google"] = &config.OAuthProviderConfig{
		ClientID: googleID, ClientSecret: googleSecret, Enabled: true,
	}

	// GitHub — from env or test placeholder
	githubID := os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	githubSecret := os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")
	if githubID == "" {
		githubID = "test-github-client-id"
		githubSecret = "test-github-client-secret"
	}
	providerConfigs["github"] = &config.OAuthProviderConfig{
		ClientID: githubID, ClientSecret: githubSecret, Enabled: true,
	}

	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		APIURL:    "http://localhost:8080",
		Security:  defaultSecurityConfig("oa-test-secret-key-32charslongxx", "oa-test-encryption-key-32chars!!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	require.NoError(t, authInstance.Use(oauth.New(&config.OAuthModuleConfig{
		AllowSignup:         true,
		AllowAccountLinking: true,
		Providers:           providerConfigs,
	}, nil)))

	return authInstance, initAuth(t, authInstance)
}
