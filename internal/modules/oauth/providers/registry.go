package providers

import (
	"fmt"
	"regexp"
	"sort"
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
	r.RegisterConnection(provider.Name(), provider)
}

func (r *Registry) RegisterConnection(name string, provider OAuthProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = provider
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
	sort.Strings(names)
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

var connectionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func ValidConnectionID(name string) bool { return connectionIDPattern.MatchString(name) }

// RegisterBuiltinProviders creates and registers all configured OAuth providers
func RegisterBuiltinProviders(registry *Registry, providers map[string]*config.OAuthProviderConfig, apiURL, basePath string) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cfg := providers[name]
		if cfg == nil || !cfg.Enabled {
			continue
		}

		if !ValidConnectionID(name) {
			return fmt.Errorf("invalid OAuth connection ID %q", name)
		}
		if registry.Has(name) {
			return fmt.Errorf("duplicate OAuth connection %q", name)
		}
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return fmt.Errorf("provider '%s' requires ClientID and ClientSecret", name)
		}

		var provider OAuthProvider
		var err error

		providerType := cfg.Type
		if providerType == "" {
			providerType = name
		}
		switch providerType {
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

		registry.RegisterConnection(name, provider)
	}

	return nil
}
