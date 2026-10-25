package config

import (
	"context"
	"github.com/bete7512/goauth/pkg/types"
)

// Component is the minimal module contract accepted by Auth.Use. The existing
// Module interface remains supported. Routes, hooks and migrations are optional.
type Component interface {
	Name() string
	Init(context.Context, ModuleDependencies) error
}

// ModuleConstraints declares composition requirements, validated before Init.
// A required capability also orders its provider before the consumer.
type ModuleConstraints struct {
	Provides  []string
	Requires  []string
	Conflicts []string
}

// ConstrainedModule is implemented by modules that declare capabilities they
// provide, require or conflict with.
type ConstrainedModule interface{ Constraints() ModuleConstraints }

// ModuleShutdown is implemented by modules that release resources when the
// Auth instance shuts down.
type ModuleShutdown interface{ Shutdown(context.Context) error }

// StorageBindings declares application-wide credential stores. It is resolved
// before any module initializes so issuance and validation use the same store.
type StorageBindings struct {
	Core    types.CoreStorage
	Session types.SessionStorage
}

// StorageBindingModule is implemented by modules that supply
// application-wide credential stores.
type StorageBindingModule interface{ StorageBindings() StorageBindings }

// AdaptModule preserves the original contract for GetModule and old consumers.
func AdaptModule(c Component) Module {
	if m, ok := c.(Module); ok {
		return m
	}
	return componentAdapter{Component: c}
}

type componentAdapter struct{ Component }

func (a componentAdapter) Dependencies() []string {
	if m, ok := a.Component.(interface{ Dependencies() []string }); ok {
		return m.Dependencies()
	}
	return nil
}
func (a componentAdapter) Routes() []RouteInfo {
	if m, ok := a.Component.(interface{ Routes() []RouteInfo }); ok {
		return m.Routes()
	}
	return nil
}
func (a componentAdapter) Middlewares() []MiddlewareConfig {
	if m, ok := a.Component.(interface{ Middlewares() []MiddlewareConfig }); ok {
		return m.Middlewares()
	}
	return nil
}
func (a componentAdapter) RegisterHooks(events types.EventBus) error {
	if m, ok := a.Component.(interface{ RegisterHooks(types.EventBus) error }); ok {
		return m.RegisterHooks(events)
	}
	return nil
}
func (a componentAdapter) OpenAPISpecs() []byte {
	if m, ok := a.Component.(interface{ OpenAPISpecs() []byte }); ok {
		return m.OpenAPISpecs()
	}
	return nil
}
func (a componentAdapter) Migrations() types.ModuleMigrations {
	if m, ok := a.Component.(interface{ Migrations() types.ModuleMigrations }); ok {
		return m.Migrations()
	}
	return nil
}
func (a componentAdapter) Constraints() ModuleConstraints {
	if m, ok := a.Component.(ConstrainedModule); ok {
		return m.Constraints()
	}
	return ModuleConstraints{}
}
func (a componentAdapter) Shutdown(ctx context.Context) error {
	if m, ok := a.Component.(ModuleShutdown); ok {
		return m.Shutdown(ctx)
	}
	return nil
}

func (a componentAdapter) StorageBindings() StorageBindings {
	if m, ok := a.Component.(StorageBindingModule); ok {
		return m.StorageBindings()
	}
	return StorageBindings{}
}
