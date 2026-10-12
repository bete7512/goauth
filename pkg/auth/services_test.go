package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/stateless"
	"github.com/bete7512/goauth/pkg/types"
	store "github.com/bete7512/goauth/storage/gorm"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// This package is an external consumer: no internal services or HTTP DTOs are
// needed to sign in or authorize application routes.
func TestPublicAuthenticationAcrossStrategies(t *testing.T) {
	for _, strategy := range []types.AuthStrategy{types.StrategySession, types.StrategyStateless} {
		t.Run(string(strategy), func(t *testing.T) {
			ctx := context.Background()
			s, err := store.NewStorage(store.Config{Dialect: types.DialectTypeSqlite, DSN: ":memory:", MaxOpenConns: 1, MaxIdleConns: 1})
			require.NoError(t, err)
			a, err := auth.New(&config.Config{Storage: s, Migration: config.MigrationConfig{Auto: true}, Security: types.SecurityConfig{AuthStrategy: strategy, AuthMode: types.AuthModeBearer, JwtSecretKey: "public-contract-signing-secret-32", EncryptionKey: "public-contract-encryption-secret"}})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, a.Close()) })
			if strategy == types.StrategySession {
				require.NoError(t, a.Use(session.New(nil)))
			} else {
				require.NoError(t, a.Use(stateless.New(nil)))
			}
			require.NoError(t, a.Initialize(ctx))
			hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
			require.NoError(t, err)
			user := &models.User{ID: "test-user", Email: "test@example.com", Username: "test-user", PasswordHash: string(hash), Active: true, EmailVerified: true}
			require.NoError(t, s.Core().Users().Create(ctx, user))
			grant, err := a.SignIn(ctx, types.SignInRequest{Email: user.Email, Password: "password123"})
			require.NoError(t, err)
			require.Equal(t, types.Authenticated, grant.Status)
			principal, err := a.Authenticate(ctx, grant.AccessToken)
			require.NoError(t, err)
			require.Equal(t, user.ID, principal.UserID)
			require.Equal(t, "default", principal.RealmID)
			require.Contains(t, principal.Methods, "password")
			_, err = a.Authenticate(ctx, grant.RefreshToken)
			require.Error(t, err, "refresh credentials never authorize application requests")
			protected := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, ok := types.PrincipalFromContext(r.Context())
				require.True(t, ok)
				require.Equal(t, principal.UserID, p.UserID)
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest("GET", "/protected", nil)
			request.Header.Set("Authorization", "Bearer "+grant.AccessToken)
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			require.Equal(t, http.StatusNoContent, response.Code)
			cookieRequest := httptest.NewRequest("GET", "/protected", nil)
			cookieRequest.AddCookie(&http.Cookie{Name: "goauth_access_session", Value: grant.AccessToken})
			response = httptest.NewRecorder()
			protected.ServeHTTP(response, cookieRequest)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			var refresh http.HandlerFunc
			for _, route := range a.Routes() {
				if route.Method == "POST" && strings.HasSuffix(route.Path, "/refresh") {
					refresh = route.Handler
				}
			}
			require.NotNil(t, refresh)
			body, err := json.Marshal(map[string]string{"refresh_token": grant.RefreshToken})
			require.NoError(t, err)
			response = httptest.NewRecorder()
			refresh(response, httptest.NewRequest("POST", "/refresh", strings.NewReader(string(body))))
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			var refreshed struct {
				Data struct {
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &refreshed))
			require.NotEmpty(t, refreshed.Data.AccessToken)
			next, err := a.Authenticate(ctx, refreshed.Data.AccessToken)
			require.NoError(t, err)
			require.Equal(t, principal.AuthenticatedAt, next.AuthenticatedAt)
			require.Equal(t, principal.Methods, next.Methods)
			if strategy == types.StrategySession {
				require.NotEmpty(t, principal.SessionID)
				require.Equal(t, principal.SessionID, next.SessionID)
			}
			response = httptest.NewRecorder()
			refresh(response, httptest.NewRequest("POST", "/refresh", strings.NewReader(string(body))))
			require.GreaterOrEqual(t, response.Code, 400, "refresh replay must fail")
			require.NoError(t, s.Core().Users().(models.UserCredentialMutator).RevokeTokens(ctx, user.ID))
			_, err = a.Authenticate(ctx, refreshed.Data.AccessToken)
			require.Error(t, err)
			user, err = s.Core().Users().FindByID(ctx, user.ID)
			require.NoError(t, err)
			user.Active = false
			require.NoError(t, s.Core().Users().Update(ctx, user))
			_, err = a.SignIn(ctx, types.SignInRequest{Email: user.Email, Password: "password123"})
			require.Error(t, err)
		})
	}
}
