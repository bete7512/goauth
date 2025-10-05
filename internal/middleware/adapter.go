package middleware

import (
	"net/http"
)

// ConfigMiddlewareConfig represents middleware config from config package
type ConfigMiddlewareConfig struct {
	Name        string
	Middleware  func(http.Handler) http.Handler
	Priority    int
	ApplyTo     []string
	ExcludeFrom []string
	Global      bool
}

// ManagerAdapter adapts Manager to work with different middleware config types
type ManagerAdapter struct {
	manager *Manager
}

// NewManagerAdapter creates a new middleware manager adapter
func NewManagerAdapter(manager *Manager) *ManagerAdapter {
	return &ManagerAdapter{manager: manager}
}

// Register registers middleware using config-style MiddlewareConfig
func (a *ManagerAdapter) Register(cfg ConfigMiddlewareConfig) {
	a.manager.Register(MiddlewareConfig{
		Name:        cfg.Name,
		Middleware:  cfg.Middleware,
		Priority:    cfg.Priority,
		ApplyTo:     cfg.ApplyTo,
		ExcludeFrom: cfg.ExcludeFrom,
		Global:      cfg.Global,
	})
}

// Apply applies middlewares to a handler for a specific route
func (a *ManagerAdapter) Apply(routeName string, handler http.Handler) http.Handler {
	return a.manager.Apply(routeName, handler)
}

// ApplyGlobal applies only global middlewares to a handler
func (a *ManagerAdapter) ApplyGlobal(handler http.Handler) http.Handler {
	return a.manager.ApplyGlobal(handler)
}
