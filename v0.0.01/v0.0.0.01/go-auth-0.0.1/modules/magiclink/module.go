package magiclink

import (
	"context"

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

func (m *MagicLinkModule) Middlewares() []config.MiddlewareConfig {
	middlewareList := []config.MiddlewareConfig{
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

func (m *MagicLinkModule) RegisterHooks(events config.EventBus) error {
	return nil
}

func (m *MagicLinkModule) Dependencies() []string {
	return nil
}
