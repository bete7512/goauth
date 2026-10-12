package providers

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// oidcVerifier shares signature, issuer, audience and lifetime verification.
// The authentication transaction validates the expected nonce separately.
// Endpoints are fixed by built-in providers; token claims never select a URL.
type oidcVerifier struct {
	once     sync.Once
	verifier *oidc.IDTokenVerifier
}

func (v *oidcVerifier) verify(ctx context.Context, p *BaseProvider, issuer, jwksURL, raw string) (map[string]interface{}, error) {
	v.once.Do(func() {
		keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), p.HTTPClient()), jwksURL)
		v.verifier = oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: p.ClientID(), SupportedSigningAlgs: []string{oidc.RS256}})
	})
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}
	if token.Subject == "" {
		return nil, fmt.Errorf("ID token subject is required")
	}
	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
