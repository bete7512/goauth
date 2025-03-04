// auth/hooks/hooks.go
package hooks

import (
	"net/http"
)

// RouteHook defines a function that can be executed before or after a route handler
type RouteHook func(w http.ResponseWriter, r *http.Request) (proceed bool, err error)

// RouteHooks contains hooks for a specific route
type RouteHooks struct {
	Before []RouteHook
	After  []RouteHook
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
func (h *HookManager) RegisterBeforeHook(route string, hook RouteHook) {
	if _, exists := h.hooks[route]; !exists {
		h.hooks[route] = &RouteHooks{
			Before: []RouteHook{},
			After:  []RouteHook{},
		}
	}
	h.hooks[route].Before = append(h.hooks[route].Before, hook)
}

// RegisterAfterHook adds a hook to be executed after a route
func (h *HookManager) RegisterAfterHook(route string, hook RouteHook) {
	if _, exists := h.hooks[route]; !exists {
		h.hooks[route] = &RouteHooks{
			Before: []RouteHook{},
			After:  []RouteHook{},
		}
	}
	h.hooks[route].After = append(h.hooks[route].After, hook)
}

// ExecuteBeforeHooks executes all before hooks for a route
// Returns false if any hook signals to abort the request
func (h *HookManager) ExecuteBeforeHooks(route string, w http.ResponseWriter, r *http.Request) bool {
	hooks, exists := h.hooks[route]
	if !exists {
		return true
	}

	for _, hook := range hooks.Before {
		proceed, err := hook(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		if !proceed {
			return false
		}
	}
	return true
}

// ExecuteAfterHooks executes all after hooks for a route
func (h *HookManager) ExecuteAfterHooks(route string, w http.ResponseWriter, r *http.Request) {
	hooks, exists := h.hooks[route]
	if !exists {
		return
	}

	for _, hook := range hooks.After {
		proceed, err := hook(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !proceed {
			return
		}
	}
}

// Clear removes all hooks for a route
func (h *HookManager) Clear(route string) {
	delete(h.hooks, route)
}

// ClearAll removes all hooks
func (h *HookManager) ClearAll() {
	h.hooks = make(map[string]*RouteHooks)
}