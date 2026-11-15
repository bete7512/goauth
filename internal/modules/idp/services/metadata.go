package services

import (
	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// Discovery returns the OpenID Provider metadata (OpenID Connect Discovery
// 1.0 section 3). It states only what the module does.
func (s *idpService) Discovery() dto.DiscoveryDocument {
	return dto.DiscoveryDocument{
		Issuer:                                     s.settings.Issuer,
		AuthorizationEndpoint:                      s.settings.Endpoints.Authorization,
		TokenEndpoint:                              s.settings.Endpoints.Token,
		UserinfoEndpoint:                           s.settings.Endpoints.UserInfo,
		JWKSURI:                                    s.settings.Endpoints.JWKS,
		ScopesSupported:                            append([]string{}, supportedScopes...),
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        []string{grantTypeAuthorizationCode, grantTypeRefreshToken},
		SubjectTypesSupported:                      []string{"public"},
		IDTokenSigningAlgValuesSupported:           []string{string(s.signer.Algorithm())},
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post", "none"},
		ClaimsSupported:                            append([]string{}, supportedClaims...),
		CodeChallengeMethodsSupported:              []string{"S256"},
		ClaimsParameterSupported:                   false,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		AuthorizationResponseIssParameterSupported: true,
	}
}

// JWKS returns the public keys that verify ID tokens: the active key and
// retired keys that have not lapsed.
func (s *idpService) JWKS() types.JWKS {
	return s.signer.JWKS()
}
