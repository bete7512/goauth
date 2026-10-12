package passkeys

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/passkeys/handlers"
	"github.com/bete7512/goauth/internal/modules/passkeys/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed migrations
	migrationFS embed.FS
)

type PasskeysModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.PasskeyHandler
	service  services.PasskeyService
	config   *config.PasskeysModuleConfig
}

var _ config.Module = (*PasskeysModule)(nil)

func New(cfg *config.PasskeysModuleConfig) *PasskeysModule {
	if cfg != nil {
		snapshot := *cfg
		cfg = &snapshot
	}
	if cfg == nil {
		cfg = &config.PasskeysModuleConfig{}
	}
	cfg.RPOrigins = append([]string(nil), cfg.RPOrigins...)
	return &PasskeysModule{config: cfg}
}

func (m *PasskeysModule) Name() string {
	return string(types.PasskeysModule)
}

func (m *PasskeysModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	if m.config.RPID == "" {
		return errors.New("passkeys: RPID is required")
	}
	if len(m.config.RPOrigins) == 0 {
		return errors.New("passkeys: at least one RPOrigin is required")
	}
	if m.config.RPDisplayName == "" {
		m.config.RPDisplayName = "GoAuth"
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          m.config.RPID,
		RPDisplayName: m.config.RPDisplayName,
		RPOrigins:     m.config.RPOrigins,
	})
	if err != nil {
		return fmt.Errorf("passkeys: webauthn init: %w", err)
	}

	var passkeyStorage types.PasskeyStorage
	if m.config.CustomStorage != nil {
		passkeyStorage = m.config.CustomStorage
	} else if deps.Storage != nil {
		passkeyStorage = deps.Storage.Passkeys()
	}
	if passkeyStorage == nil {
		return errors.New("passkeys: passkey storage is required")
	}

	coreStorage := deps.Storage.Core()
	if coreStorage == nil {
		return errors.New("passkeys: core storage is required")
	}

	var securityManager types.SecurityManager
	if deps.SecurityManager != nil {
		securityManager = deps.SecurityManager
	} else {
		securityManager = security.NewSecurityManager(deps.Config.Security)
	}

	m.service = services.NewPasskeyService(
		deps,
		m.config,
		wa,
		passkeyStorage.Passkeys(),
		coreStorage.Users(),
		securityManager,
	)
	m.handlers = handlers.NewPasskeyHandler(m.service, deps)
	return nil
}

func (m *PasskeysModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	auth := []types.MiddlewareName{types.MiddlewareAuth}
	return []config.RouteInfo{
		{
			Name:        string(types.RoutePasskeysRegisterBegin),
			Path:        "/passkeys/register/begin",
			Method:      http.MethodPost,
			Handler:     m.handlers.BeginRegistration,
			Middlewares: auth,
		},
		{
			Name:        string(types.RoutePasskeysRegisterFinish),
			Path:        "/passkeys/register/finish",
			Method:      http.MethodPost,
			Handler:     m.handlers.FinishRegistration,
			Middlewares: auth,
		},
		{
			Name:    string(types.RoutePasskeysLoginBegin),
			Path:    "/passkeys/login/begin",
			Method:  http.MethodPost,
			Handler: m.handlers.BeginLogin,
		},
		{
			Name:    string(types.RoutePasskeysLoginFinish),
			Path:    "/passkeys/login/finish",
			Method:  http.MethodPost,
			Handler: m.handlers.FinishLogin,
		},
		{
			Name:        string(types.RoutePasskeysList),
			Path:        "/passkeys",
			Method:      http.MethodGet,
			Handler:     m.handlers.List,
			Middlewares: auth,
		},
		{
			Name:        string(types.RoutePasskeysDelete),
			Path:        "/passkeys/{id}",
			Method:      http.MethodDelete,
			Handler:     m.handlers.Delete,
			Middlewares: auth,
		},
		{
			Name:        string(types.RoutePasskeysRename),
			Path:        "/passkeys/{id}",
			Method:      http.MethodPut,
			Handler:     m.handlers.Rename,
			Middlewares: auth,
		},
	}
}

func (m *PasskeysModule) Middlewares() []config.MiddlewareConfig    { return nil }
func (m *PasskeysModule) RegisterHooks(events types.EventBus) error { return nil }
func (m *PasskeysModule) Dependencies() []string                    { return []string{string(types.CoreModule)} }
func (m *PasskeysModule) OpenAPISpecs() []byte                      { return openapiSpec }
func (m *PasskeysModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}
