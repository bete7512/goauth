// Package dto holds the request and response bodies of the idp module.
package dto

import "time"

// DiscoveryDocument is the OpenID Provider metadata served at
// /.well-known/openid-configuration (OpenID Connect Discovery 1.0 section 3).
type DiscoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// TokenResponse is a successful token endpoint response (RFC 6749 section
// 5.1, OpenID Connect Core section 3.1.3.3).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthError is the error body of the protocol endpoints (RFC 6749 section 5.2).
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ConsentClient describes the application that asks to sign the user in.
type ConsentClient struct {
	ClientID  string `json:"client_id"`
	Name      string `json:"name"`
	LogoURI   string `json:"logo_uri,omitempty"`
	ClientURI string `json:"client_uri,omitempty"`
}

// ConsentScope is one scope of a pending request.
type ConsentScope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// PreviouslyGranted is true when the user already approved the scope
	// for this application.
	PreviouslyGranted bool `json:"previously_granted"`
}

// ConsentDetails describes a pending sign-in request to the signed-in user.
type ConsentDetails struct {
	RequestID string        `json:"request_id"`
	Client    ConsentClient `json:"client"`
	// RedirectHost is where the user is sent after the decision.
	RedirectHost string         `json:"redirect_host"`
	Scopes       []ConsentScope `json:"scopes"`
	// ConsentRequired is false when there is nothing to ask: the page can
	// approve the request without showing a prompt.
	ConsentRequired bool `json:"consent_required"`
	// LoginRequired is true when the application asked for a fresh sign-in
	// and the user's current one is too old. Approving fails with
	// IDP_LOGIN_REQUIRED until the user signs in again.
	LoginRequired bool `json:"login_required"`
	// LoginHint is the account the application expects, if it named one.
	LoginHint string    `json:"login_hint,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ConsentRedirect tells the consent page where to send the browser.
type ConsentRedirect struct {
	RedirectTo string `json:"redirect_to"`
}

// Grant is an application the user is connected to.
type Grant struct {
	ID         string     `json:"id"`
	ClientID   string     `json:"client_id"`
	ClientName string     `json:"client_name"`
	LogoURI    string     `json:"logo_uri,omitempty"`
	ClientURI  string     `json:"client_uri,omitempty"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// ClientRequest creates or replaces a client application.
type ClientRequest struct {
	// ClientID is the public identifier. Only read when creating; empty
	// generates one.
	ClientID     string   `json:"client_id,omitempty"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	// Scopes limits what the client may request. Empty means openid,
	// profile and email.
	Scopes []string `json:"scopes,omitempty"`
	// Public marks an application that cannot keep a secret. It gets no
	// secret and must use PKCE.
	Public bool `json:"public,omitempty"`
	// RequirePKCE defaults to true. A public client always requires it.
	RequirePKCE *bool  `json:"require_pkce,omitempty"`
	SkipConsent bool   `json:"skip_consent,omitempty"`
	LogoURI     string `json:"logo_uri,omitempty"`
	ClientURI   string `json:"client_uri,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}

// Client is a registered client application. ClientSecret is present only in
// the response that creates the client or rotates its secret.
type Client struct {
	ID           string     `json:"id"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Name         string     `json:"name"`
	Public       bool       `json:"public"`
	RedirectURIs []string   `json:"redirect_uris"`
	Scopes       []string   `json:"scopes"`
	RequirePKCE  bool       `json:"require_pkce"`
	SkipConsent  bool       `json:"skip_consent"`
	LogoURI      string     `json:"logo_uri,omitempty"`
	ClientURI    string     `json:"client_uri,omitempty"`
	Managed      bool       `json:"managed"`
	Disabled     bool       `json:"disabled"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}
