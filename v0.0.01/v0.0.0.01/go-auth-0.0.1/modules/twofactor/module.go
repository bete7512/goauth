package twofactor

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/modules/twofactor/models"
	"github.com/bete7512/goauth/pkg/config"
)

type TwoFactorModule struct{}

var _ config.Module = (*TwoFactorModule)(nil)

func New() *TwoFactorModule {
	return &TwoFactorModule{}
}
func (m *TwoFactorModule) Name() string {
	return string(config.TwoFactorModule)
}

func (m *TwoFactorModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	return nil
}

func (m *TwoFactorModule) Routes() []config.RouteInfo {
	return nil
}

func (m *TwoFactorModule) Middlewares() []func(http.Handler) http.Handler {
	middlewareList := []func(http.Handler) http.Handler{
		// Add any module-specific middlewares here
	}
	return middlewareList
}

func (m *TwoFactorModule) Models() []interface{} {
	models := []interface{}{
		models.TwoFactor{},
	}
	return models
}

func (m *TwoFactorModule) Hooks() config.Hooks {
	return config.Hooks{}
}

func (m *TwoFactorModule) Dependencies() []string {
	return nil
}
