package providers

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
)

var connectionID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidConnectionID reports whether name is safe to appear in a URL path and cookie name.
func ValidConnectionID(name string) bool {
	return connectionID.MatchString(name)
}

// Registry holds the configured connections by name.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]ServiceProvider
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]ServiceProvider)}
}

// Register adds a connection. It fails on an invalid or duplicate name.
func (r *Registry) Register(provider ServiceProvider) error {
	if provider == nil {
		return fmt.Errorf("saml: nil provider")
	}
	name := provider.Name()
	if !ValidConnectionID(name) {
		return fmt.Errorf("saml: invalid connection name %q (lowercase letters, digits, '-' and '_' only)", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("saml: duplicate connection %q", name)
	}
	r.providers[name] = provider
	return nil
}

// Get returns the connection with the given name.
func (r *Registry) Get(name string) (ServiceProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.providers[name]
	return provider, ok
}

// Has reports whether a connection with the given name exists.
func (r *Registry) Has(name string) bool {
	_, ok := r.Get(name)
	return ok
}

// List returns the connection names, sorted.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of connections.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}
