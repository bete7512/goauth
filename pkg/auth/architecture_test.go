package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	storage "github.com/bete7512/goauth/storage/gorm"
	"github.com/stretchr/testify/require"
)

type component struct {
	name        string
	deps        []string
	routes      []config.RouteInfo
	constraints config.ModuleConstraints
	init        func() error
	stop        func() error
}

func (m *component) Name() string { return m.name }
func (m *component) Init(context.Context, config.ModuleDependencies) error {
	if m.init != nil {
		return m.init()
	}
	return nil
}
func (m *component) Dependencies() []string                { return m.deps }
func (m *component) Routes() []config.RouteInfo            { return m.routes }
func (m *component) Constraints() config.ModuleConstraints { return m.constraints }
func (m *component) Shutdown(context.Context) error {
	if m.stop != nil {
		return m.stop()
	}
	return nil
}

func newAuth(t *testing.T) (*auth.Auth, *config.Config) {
	t.Helper()
	store, err := storage.NewStorage(storage.Config{Dialect: types.DialectTypeSqlite, DSN: ":memory:"})
	require.NoError(t, err)
	cfg := &config.Config{Storage: store, Security: types.SecurityConfig{JwtSecretKey: "01234567890123456789012345678901", EncryptionKey: "01234567890123456789012345678901"}}
	a, err := auth.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	return a, cfg
}

func TestDependencyPlanIgnoresRegistrationOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		a, _ := newAuth(t)
		var order []string
		provider := &component{name: "z-provider", constraints: config.ModuleConstraints{Provides: []string{"test.service"}}, init: func() error { order = append(order, "provider"); return nil }}
		consumer := &component{name: "a-consumer", constraints: config.ModuleConstraints{Requires: []string{"test.service"}}, init: func() error { order = append(order, "consumer"); return nil }}
		modules := []*component{consumer, provider}
		if reverse {
			modules[0], modules[1] = modules[1], modules[0]
		}
		for _, m := range modules {
			require.NoError(t, a.Use(m))
		}
		require.NoError(t, a.Initialize(context.Background()))
		require.Equal(t, []string{"provider", "consumer"}, order)
		require.Error(t, a.Use(&component{name: "late"}))
	}
}

func TestInvalidGraphsNeverInitialize(t *testing.T) {
	tests := []struct {
		name    string
		modules []*component
		want    string
	}{
		{"missing", []*component{{name: "a", deps: []string{"missing"}}}, "missing dependency"},
		{"cycle", []*component{{name: "a", deps: []string{"b"}}, {name: "b", deps: []string{"a"}}}, "dependency cycle"},
		{"capability", []*component{{name: "a", constraints: config.ModuleConstraints{Requires: []string{"missing"}}}}, "missing capability"},
		{"conflict", []*component{{name: "a", constraints: config.ModuleConstraints{Conflicts: []string{"b"}}}, {name: "b"}}, "conflicts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := newAuth(t)
			for _, m := range tt.modules {
				m.init = func() error { t.Fatal("initialized invalid graph"); return nil }
				require.NoError(t, a.Use(m))
			}
			require.ErrorContains(t, a.Initialize(context.Background()), tt.want)
			require.Empty(t, a.Routes())
		})
	}
}

func TestStartupRejectsIncompleteRoutes(t *testing.T) {
	handler := func(http.ResponseWriter, *http.Request) {}
	for _, tc := range []struct {
		name   string
		routes []config.RouteInfo
		want   string
	}{
		{"missing protection", []config.RouteInfo{{Name: "test", Method: "GET", Path: "/test", Handler: handler, Middlewares: []types.MiddlewareName{"missing.auth"}}}, "required middleware"},
		{"duplicate name", []config.RouteInfo{{Name: "test", Method: "GET", Path: "/a", Handler: handler}, {Name: "test", Method: "GET", Path: "/b", Handler: handler}}, "duplicate route"},
		{"duplicate endpoint", []config.RouteInfo{{Name: "a", Method: "GET", Path: "/test", Handler: handler}, {Name: "b", Method: "GET", Path: "/test", Handler: handler}}, "route collision"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newAuth(t)
			require.NoError(t, a.Use(&component{name: "test", routes: tc.routes}))
			require.ErrorContains(t, a.Initialize(context.Background()), tc.want)
			require.Empty(t, a.Routes())
		})
	}
}

func TestRequireAuthFailsClosedBeforeAndAfterLifecycle(t *testing.T) {
	a, _ := newAuth(t)
	h := a.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unprotected handler invoked") }))
	request := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		return w.Code
	}
	require.Equal(t, http.StatusServiceUnavailable, request())
	require.NoError(t, a.Initialize(context.Background()))
	require.Equal(t, http.StatusUnauthorized, request())
	require.NoError(t, a.Close())
	require.Equal(t, http.StatusServiceUnavailable, request())
}

func TestStartupFailureUnwindsAndAggregates(t *testing.T) {
	a, _ := newAuth(t)
	var order []string
	require.NoError(t, a.Use(&component{name: "a", stop: func() error { order = append(order, "a"); return nil }}))
	require.NoError(t, a.Use(&component{name: "b", deps: []string{"a"}, init: func() error { return errors.New("startup failure") }, stop: func() error { order = append(order, "b"); return errors.New("cleanup failure") }}))
	err := a.Initialize(context.Background())
	require.ErrorContains(t, err, "startup failure")
	require.ErrorContains(t, err, "cleanup failure")
	require.Equal(t, []string{"b", "a"}, order)
	require.Error(t, a.Initialize(context.Background()))
	_ = a.Close()
	require.Equal(t, []string{"b", "a"}, order)
}

func TestConfigIsSnapshotted(t *testing.T) {
	a, original := newAuth(t)
	original.BasePath = "/mutated"
	original.Security.JwtSecretKey = "changed"
	copy := a.Config()
	copy.BasePath = "/changed-again"
	require.Equal(t, "/auth", a.Config().BasePath)
	require.NotEqual(t, "changed", a.Config().Security.JwtSecretKey)
	require.NoError(t, a.Initialize(context.Background()))
}

func TestInvalidSigningKeyFailsConstruction(t *testing.T) {
	_, cfg := newAuth(t)
	cfg.Security.JWTAlgorithm = types.JWTAlgorithmRS256
	cfg.Security.JWTPrivateKeyPEM = []byte("not a key")
	_, err := auth.New(cfg)
	require.ErrorContains(t, err, "invalid JWT configuration")
}
