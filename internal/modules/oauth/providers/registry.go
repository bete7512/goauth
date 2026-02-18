package providers

import (
	"fmt"
	"sync"

	"github.com/bete7512/goauth/pkg/config"
)

// Registry manages OAuth provider instances
type Registry struct {
	mu        sync.RWMutex
	providers map[string]OAuthProvider
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]OAuthProvider),
	}
}

// Register adds a provider to the registry
func (r *Registry) Register(provider OAuthProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
}

// Get retrieves a provider by name
func (r *Registry) Get(name string) (OAuthProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider '%s' not found", name)
	}
	return provider, nil
}

// Has checks if a provider is registered
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.providers[name]
	return ok
}

// List returns all registered provider names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}

// Count returns the number of registered providers
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// Provider name constants
const (
	ProviderGoogle    = "google"
	ProviderGitHub    = "github"
	ProviderMicrosoft = "microsoft"
	ProviderDiscord   = "discord"
)

// RegisterBuiltinProviders creates and registers all configured OAuth providers
func RegisterBuiltinProviders(registry *Registry, providers map[string]*config.OAuthProviderConfig, apiURL, basePath string) error {
	for name, cfg := range providers {
		if cfg == nil || !cfg.Enabled {
			continue
		}

		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return fmt.Errorf("provider '%s' requires ClientID and ClientSecret", name)
		}

		var provider OAuthProvider
		var err error

		switch name {
		case ProviderGoogle:
			provider, err = NewGoogleProvider(cfg, apiURL, basePath)
		case ProviderGitHub:
			provider, err = NewGitHubProvider(cfg, apiURL, basePath)
		case ProviderMicrosoft:
			provider, err = NewMicrosoftProvider(cfg, apiURL, basePath)
		case ProviderDiscord:
			provider, err = NewDiscordProvider(cfg, apiURL, basePath)
		default:
			return fmt.Errorf("unknown provider: %s", name)
		}

		if err != nil {
			return fmt.Errorf("failed to create provider '%s': %w", name, err)
		}

		registry.Register(provider)
	}

	return nil
}
