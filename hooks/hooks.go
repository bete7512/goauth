// auth/hooks/hooks.go
package hooks

import (
	"fmt"
	"net/http"
)

// RouteHook defines a function that can be executed before or after a route handler
type RouteHook func(w http.ResponseWriter, r *http.Request) (proceed bool, err error)

// RouteHooks contains hooks for a specific route
type RouteHooks struct {
	Before RouteHook
	After  RouteHook
}

// HookManager manages hooks for different routes
type HookManager struct {
	hooks map[string]*RouteHooks
}

// NewHookManager creates a new hook manager
func NewHookManager() *HookManager {
	return &HookManager{
		hooks: make(map[string]*RouteHooks),
	}
}

// RegisterBeforeHook adds a hook to be executed before a route
func (h *HookManager) RegisterBeforeHook(route string, hook RouteHook) error {
	_, exists := h.hooks[route]
	if !exists {
		h.hooks[route] = &RouteHooks{
			Before: hook,
		}
		return nil
	}
	if h.hooks[route].Before == nil {
		h.hooks[route].Before = hook
		return nil
	}

	return fmt.Errorf("hook already exists for route %s", route)
}

// RegisterAfterHook adds a hook to be executed after a route
func (h *HookManager) RegisterAfterHook(route string, hook RouteHook) error {

	_, exists := h.hooks[route]
	if !exists {
		h.hooks[route] = &RouteHooks{
			After: hook,
		}
		return nil
	}

	if h.hooks[route].After == nil {
		h.hooks[route].After = hook
		return nil
	}

	return fmt.Errorf("hook already exists for route %s", route)
}

// Returns false if any hook signals to abort the request
func (h *HookManager) ExecuteBeforeHooks(route string, w http.ResponseWriter, r *http.Request) bool {
	hooks, exists := h.hooks[route]
	if !exists && hooks.Before == nil {
		return true
	}

	proceed, err := hooks.Before(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if !proceed {
		return false
	}
	return true
}

// ExecuteAfterHooks executes all after hooks for a route
func (h *HookManager) ExecuteAfterHooks(route string, w http.ResponseWriter, r *http.Request) {
	hooks, exists := h.hooks[route]
	if !exists && hooks.After == nil {
		return
	}
	_, err := hooks.After(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func (h *HookManager) GetHooks() map[string]*RouteHooks {
	return h.hooks
}

func (h *HookManager) GetBeforeHook(route string) *RouteHook {
	if hooks, exists := h.hooks[route]; exists && hooks.Before != nil {
		return &hooks.Before
	}
	return nil
}

func (h *HookManager) GetAfterHook(route string) *RouteHook {
	if hooks, exists := h.hooks[route]; exists && hooks.After != nil {
		return &hooks.After
	}
	return nil
}

func (h *HookManager) SetHook(route string, hooks *RouteHooks) {
	h.hooks[route] = hooks
}

// Clear removes all hooks for a route
func (h *HookManager) Clear(route string) {
	delete(h.hooks, route)
}

// ClearAll removes all hooks
func (h *HookManager) ClearAll() {
	h.hooks = make(map[string]*RouteHooks)
}
