package magiclink

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/pkg/config"
)

type MagicLinkModule struct{}

var _ config.Module = (*MagicLinkModule)(nil)

func New() *MagicLinkModule {
	return &MagicLinkModule{}
}
func (m *MagicLinkModule) Name() string {
	return string(config.MagicLinkModule)
}

func (m *MagicLinkModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	return nil
}

func (m *MagicLinkModule) Routes() []config.RouteInfo {
	return nil
}

func (m *MagicLinkModule) Middlewares() []func(http.Handler) http.Handler {
	middlewareList := []func(http.Handler) http.Handler{
		// Add any module-specific middlewares here
	}
	return middlewareList
}

func (m *MagicLinkModule) Models() []interface{} {
	models := []interface{}{
		// Add any module-specific models here
	}
	return models
}

func (m *MagicLinkModule) Hooks() config.Hooks {
	return config.Hooks{}
}

func (m *MagicLinkModule) Dependencies() []string {
	return nil
}
