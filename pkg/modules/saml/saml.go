// Package saml exposes the SAML 2.0 service-provider module.
// Import this package instead of internal/modules/saml.
//
// The module stores linked subjects in the accounts table owned by the OAuth
// module, so register oauth.New(nil) alongside it.
package saml

import (
	internal "github.com/bete7512/goauth/internal/modules/saml"
	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates the SAML module. Pass nil for cfg to use safe defaults.
func New(cfg *config.SAMLModuleConfig) config.Module {
	return internal.New(cfg)
}

// ServiceProvider is implemented by trusted application code that wants to
// supply its own connection; it must verify responses completely before
// returning an Identity.
type ServiceProvider = providers.ServiceProvider

// Identity is what a verified assertion says about the user.
type Identity = providers.Identity

// NewWithProviders creates the SAML module with custom connections installed.
// It fails on an invalid or duplicate connection name.
func NewWithProviders(cfg *config.SAMLModuleConfig, connections []ServiceProvider) (config.Module, error) {
	module := internal.New(cfg)
	for _, provider := range connections {
		if err := module.RegisterProvider(provider); err != nil {
			return nil, err
		}
	}
	return module, nil
}
