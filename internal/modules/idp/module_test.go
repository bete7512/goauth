package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Info(string, ...interface{})                      {}
func (noopLogger) Error(string, ...interface{})                     {}
func (noopLogger) Debug(string, ...interface{})                     {}
func (noopLogger) Warn(string, ...interface{})                      {}
func (noopLogger) Trace(string, ...interface{})                     {}
func (noopLogger) Infof(string, ...interface{})                     {}
func (noopLogger) Tracef(string, ...interface{})                    {}
func (noopLogger) Errorf(string, ...interface{})                    {}
func (noopLogger) Debugf(string, ...interface{})                    {}
func (noopLogger) Warnf(string, ...interface{})                     {}
func (noopLogger) Fatalf(string, ...interface{})                    {}
func (l noopLogger) WithFields(map[string]interface{}) types.Logger { return l }

type stubCoreStorage struct{}

func (stubCoreStorage) Users() models.UserRepository   { return nil }
func (stubCoreStorage) Tokens() models.TokenRepository { return nil }
func (stubCoreStorage) WithTransaction(context.Context, func(types.CoreStorage) error) error {
	return nil
}

func signingKey(t *testing.T) config.IDPSigningKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return config.IDPSigningKey{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})}
}

func moduleDeps(storage types.Storage) config.ModuleDependencies {
	return config.ModuleDependencies{
		Logger:  noopLogger{},
		Storage: storage,
		Config: &config.Config{
			APIURL: "https://api.example.com", BasePath: "/auth",
			Security:       types.SecurityConfig{JwtSecretKey: "test-secret-key-for-unit-tests!!"},
			Core:           &config.CoreConfig{},
			FrontendConfig: &config.FrontendConfig{URL: "https://app.example.com"},
		},
	}
}

func TestModuleContract(t *testing.T) {
	var _ config.Module = New(nil)
	m := New(nil)
	require.Equal(t, string(types.IDPModule), m.Name())
	require.Equal(t, "idp", m.Name())
	require.Equal(t, []string{string(types.CoreModule)}, m.Dependencies())
	require.Nil(t, m.Routes(), "no routes before Init")
	require.Nil(t, m.Middlewares())
	require.NoError(t, m.RegisterHooks(nil))
	require.NotEmpty(t, m.OpenAPISpecs())

	migrations := m.Migrations()
	require.NotEmpty(t, migrations, "the module owns tables")

	_, authErr := m.RevokeUserGrants(context.Background(), "user-1")
	require.NotNil(t, authErr, "the module does nothing before Init")
}

// The admin API is protected by the admin module's middleware, so enabling
// it makes that module a dependency.
func TestAdminAPINeedsTheAdminModule(t *testing.T) {
	m := New(&config.IDPModuleConfig{AdminAPI: true})
	require.Equal(t, []string{string(types.CoreModule), string(types.AdminModule)}, m.Dependencies())
}

func TestNewCopiesConfig(t *testing.T) {
	cfg := &config.IDPModuleConfig{
		SigningKey: config.IDPSigningKey{PrivateKeyPEM: []byte("key")},
		Clients:    []config.IDPClientConfig{{ClientID: "app", RedirectURIs: []string{"https://app.example.com/cb"}, Scopes: []string{"openid"}}},
	}
	m := New(cfg)
	cfg.SigningKey.PrivateKeyPEM[0] = 'X'
	cfg.Clients[0].ClientID = "changed"
	cfg.Clients[0].RedirectURIs[0] = "https://evil.example.com/cb"
	cfg.Clients[0].Scopes[0] = "changed"
	cfg.Clients = append(cfg.Clients, config.IDPClientConfig{ClientID: "added"})

	require.Equal(t, []byte("key"), m.config.SigningKey.PrivateKeyPEM)
	require.Len(t, m.config.Clients, 1)
	require.Equal(t, "app", m.config.Clients[0].ClientID)
	require.Equal(t, []string{"https://app.example.com/cb"}, m.config.Clients[0].RedirectURIs)
	require.Equal(t, []string{"openid"}, m.config.Clients[0].Scopes)
}

func TestInitFailsWithADescriptiveError(t *testing.T) {
	ctx := context.Background()

	err := New(nil).Init(ctx, moduleDeps(nil))
	require.ErrorContains(t, err, "idp: SigningKey is required")
	require.ErrorContains(t, err, "openssl genrsa", "the error says how to make a key")

	err = New(&config.IDPModuleConfig{SigningKey: signingKey(t)}).Init(ctx, moduleDeps(nil))
	require.ErrorContains(t, err, "idp: core storage is required")

	err = New(&config.IDPModuleConfig{SigningKey: signingKey(t)}).Init(ctx, moduleDeps(&types.StorageSet{CoreStore: stubCoreStorage{}}))
	require.ErrorContains(t, err, "Storage.IDP returned nil")
}
