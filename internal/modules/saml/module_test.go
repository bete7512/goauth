package saml

import (
	"context"
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

func TestModuleContract(t *testing.T) {
	var _ config.Module = New(nil)
	m := New(nil)
	require.Equal(t, string(types.SAMLModule), m.Name())
	require.Equal(t, []string{string(types.CoreModule), string(types.OAuthModule)}, m.Dependencies())
	require.Nil(t, m.Routes(), "no routes before Init")
	require.Nil(t, m.Middlewares())
	require.NoError(t, m.RegisterHooks(nil))
	require.NotEmpty(t, m.OpenAPISpecs())
	require.Empty(t, m.Migrations())
	require.True(t, m.config.AllowSignup)
	require.True(t, m.config.TrustEmail)
}

func TestNewCopiesConfig(t *testing.T) {
	provider := &config.SAMLProviderConfig{MetadataURL: "https://idp/metadata"}
	cfg := &config.SAMLModuleConfig{Providers: map[string]*config.SAMLProviderConfig{"idp": provider}}
	m := New(cfg)
	provider.MetadataURL = "changed"
	cfg.Providers["other"] = &config.SAMLProviderConfig{}
	require.Equal(t, "https://idp/metadata", m.config.Providers["idp"].MetadataURL)
	require.Len(t, m.config.Providers, 1)
	require.Positive(t, m.config.RequestTTL)
}

func TestInitRequiresStorageAndAPIURL(t *testing.T) {
	m := New(nil)
	err := m.Init(context.Background(), config.ModuleDependencies{Logger: noopLogger{}, Config: &config.Config{}})
	require.ErrorContains(t, err, "core storage is required")

	m = New(&config.SAMLModuleConfig{CustomCoreStorage: stubCoreStorage{}})
	err = m.Init(context.Background(), config.ModuleDependencies{Logger: noopLogger{}, Config: &config.Config{}})
	require.ErrorContains(t, err, "custom stores")
}

func TestRegisterProviderFrozenAfterInit(t *testing.T) {
	m := New(nil)
	_ = m.Init(context.Background(), config.ModuleDependencies{Logger: noopLogger{}, Config: &config.Config{}})
	require.ErrorContains(t, m.RegisterProvider(nil), "frozen")
}
