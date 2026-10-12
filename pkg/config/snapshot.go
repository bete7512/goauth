package config

import "maps"
import "github.com/bete7512/goauth/pkg/types"

// Clone snapshots static configuration. Injected services (storage, logger,
// claims provider and backend) retain their identity and own synchronization.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	copy := *c
	copy.Security.DecryptionKeys = maps.Clone(c.Security.DecryptionKeys)
	copy.Security.RetainedJWTKeys = append([]types.JWTVerificationKey(nil), c.Security.RetainedJWTKeys...)
	for i := range copy.Security.RetainedJWTKeys {
		copy.Security.RetainedJWTKeys[i].PublicKeyPEM = append([]byte(nil), c.Security.RetainedJWTKeys[i].PublicKeyPEM...)
	}
	copy.Security.JWTPrivateKeyPEM = append([]byte(nil), c.Security.JWTPrivateKeyPEM...)
	copy.Security.JWTPublicKeyPEM = append([]byte(nil), c.Security.JWTPublicKeyPEM...)
	copy.ModuleConfigs = maps.Clone(c.ModuleConfigs)
	if c.Core != nil {
		v := *c.Core
		copy.Core = &v
	}
	if c.FrontendConfig != nil {
		v := *c.FrontendConfig
		copy.FrontendConfig = &v
	}
	return &copy
}
