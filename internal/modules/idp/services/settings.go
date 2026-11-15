package services

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// Defaults applied by ResolveSettings.
const (
	defaultIDTokenTTL      = time.Hour
	defaultAccessTokenTTL  = time.Hour
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultRefreshLeeway   = 10 * time.Second
	defaultCodeTTL         = 60 * time.Second
	defaultRequestTTL      = 10 * time.Minute
	defaultConsentPath     = "/oidc/consent"
	// issuerPath is where the module's routes live under the base path.
	issuerPath = "/oidc"
	// maxCodeTTL keeps authorization codes short-lived (RFC 6749 section
	// 4.1.2 recommends at most ten minutes).
	maxCodeTTL = 10 * time.Minute
	// minClientSecretLength is the shortest client secret accepted from
	// configuration. Secrets are stored as an unsalted digest, which is only
	// safe for values that cannot be guessed.
	minClientSecretLength = 32
)

// Endpoints are the absolute URLs advertised in the discovery document.
type Endpoints struct {
	Authorization string
	Token         string
	UserInfo      string
	JWKS          string
}

// Settings is the validated configuration the service runs on.
type Settings struct {
	Issuer    string
	Endpoints Endpoints
	// ConsentURL and ErrorURL are the host's frontend pages.
	ConsentURL string
	ErrorURL   string
	Signer     *security.TokenSigner

	IDTokenTTL         time.Duration
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	RefreshReuseLeeway time.Duration
	CodeTTL            time.Duration
	RequestTTL         time.Duration

	AdminAPI    bool
	Claims      config.IDPClaimsFunc
	SeedClients []config.IDPClientConfig
}

// ResolveSettings validates the module configuration against the host
// configuration and fills in defaults. Errors are written for the library
// user: they name the field to fix.
func ResolveSettings(deps config.ModuleDependencies, cfg *config.IDPModuleConfig) (*Settings, error) {
	if deps.Config == nil {
		return nil, errors.New("idp: config is required")
	}
	if cfg == nil {
		cfg = &config.IDPModuleConfig{}
	}
	insecureAllowed := deps.Config.Security.Session.AllowInsecureCookies

	apiURL := strings.TrimRight(deps.Config.APIURL, "/")
	if apiURL == "" {
		return nil, errors.New("idp: Config.APIURL is required (the issuer and the endpoint URLs in the discovery document are built from it)")
	}
	base := apiURL + deps.Config.BasePath
	if _, err := validateServerURL(base, insecureAllowed); err != nil {
		return nil, fmt.Errorf("idp: Config.APIURL %w", err)
	}

	issuer := strings.TrimRight(cfg.Issuer, "/")
	if issuer == "" {
		issuer = base + issuerPath
	}
	issuerURL, err := validateServerURL(issuer, insecureAllowed)
	if err != nil {
		return nil, fmt.Errorf("idp: Issuer %w", err)
	}
	if issuerURL.RawQuery != "" {
		return nil, errors.New("idp: Issuer must not contain a query")
	}

	settings := &Settings{
		Issuer: issuer,
		// The endpoints are addressed relative to the issuer, so a host that
		// publishes the issuer under another address (a reverse proxy)
		// advertises endpoints clients can reach.
		Endpoints: Endpoints{
			Authorization: issuer + "/authorize",
			Token:         issuer + "/token",
			UserInfo:      issuer + "/userinfo",
			JWKS:          issuer + "/jwks",
		},
		IDTokenTTL:         positiveOr(cfg.IDTokenTTL, defaultIDTokenTTL),
		AccessTokenTTL:     positiveOr(cfg.AccessTokenTTL, defaultAccessTokenTTL),
		RefreshTokenTTL:    positiveOr(cfg.RefreshTokenTTL, defaultRefreshTokenTTL),
		RefreshReuseLeeway: cfg.RefreshTokenReuseLeeway,
		CodeTTL:            positiveOr(cfg.AuthorizationCodeTTL, defaultCodeTTL),
		RequestTTL:         positiveOr(cfg.AuthorizationRequestTTL, defaultRequestTTL),
		AdminAPI:           cfg.AdminAPI,
		Claims:             cfg.Claims,
		SeedClients:        cfg.Clients,
	}
	if settings.CodeTTL > maxCodeTTL {
		return nil, fmt.Errorf("idp: AuthorizationCodeTTL must not exceed %s", maxCodeTTL)
	}
	switch {
	case settings.RefreshReuseLeeway == 0:
		settings.RefreshReuseLeeway = defaultRefreshLeeway
	case settings.RefreshReuseLeeway < 0:
		settings.RefreshReuseLeeway = 0
	}

	// Consent and error pages.
	settings.ConsentURL = cfg.ConsentURL
	if settings.ConsentURL == "" && deps.Config.FrontendConfig != nil && deps.Config.FrontendConfig.URL != "" {
		settings.ConsentURL = strings.TrimRight(deps.Config.FrontendConfig.URL, "/") + defaultConsentPath
	}
	if settings.ConsentURL == "" {
		return nil, errors.New("idp: ConsentURL is required (the page of your frontend where the user signs in and approves a request), or set FrontendConfig.URL to use <URL>/oidc/consent")
	}
	if err := validateFrontendURL(settings.ConsentURL); err != nil {
		return nil, fmt.Errorf("idp: ConsentURL %w", err)
	}
	if cfg.ErrorURL != "" {
		if err := validateFrontendURL(cfg.ErrorURL); err != nil {
			return nil, fmt.Errorf("idp: ErrorURL %w", err)
		}
		settings.ErrorURL = cfg.ErrorURL
	}

	if settings.Signer, err = resolveSigner(deps, cfg.SigningKey); err != nil {
		return nil, err
	}
	if err := validateSeedClients(cfg.Clients); err != nil {
		return nil, err
	}
	return settings, nil
}

// resolveSigner builds the ID token signer from the module's own RSA key and
// refuses a key that also signs GoAuth's access tokens.
func resolveSigner(deps config.ModuleDependencies, key config.IDPSigningKey) (*security.TokenSigner, error) {
	const help = "generate one with: openssl genrsa -out idp-signing-key.pem 2048"
	if len(key.PrivateKeyPEM) == 0 && key.PrivateKeyFile == "" {
		return nil, errors.New("idp: SigningKey is required: set IDPModuleConfig.SigningKey.PrivateKeyPEM or PrivateKeyFile to an RSA private key that signs ID tokens (" + help + ")")
	}
	for _, retired := range key.RetiredKeys {
		if retired.Algorithm != types.JWTAlgorithmRS256 {
			return nil, errors.New("idp: SigningKey.RetiredKeys must be RS256 public keys")
		}
	}
	// RS256 is the one signature algorithm every OpenID Connect client must
	// support, so the key has to be an RSA key.
	signer, err := security.NewTokenSigner(types.SecurityConfig{
		JWTAlgorithm:      types.JWTAlgorithmRS256,
		JWTPrivateKeyPEM:  key.PrivateKeyPEM,
		JWTPrivateKeyFile: key.PrivateKeyFile,
		JWTKeyID:          key.KeyID,
		RetainedJWTKeys:   key.RetiredKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("idp: SigningKey must be an RSA private key of at least 2048 bits (%s): %w", help, err)
	}

	// An ID token has the same JOSE type as GoAuth's own access tokens. A
	// key of its own is what keeps one from ever being accepted as the other.
	const shared = "idp: SigningKey must not be the key that signs GoAuth's access tokens (Security.JWTPrivateKeyPEM or a retained key): an ID token handed to another application could then be used as an access token here. Use a separate key (" + help + ")"
	if manager, ok := deps.SecurityManager.(interface {
		TokenSigner() (*security.TokenSigner, error)
	}); ok {
		if core, err := manager.TokenSigner(); err == nil && signer.SharesKeyWith(core) {
			return nil, errors.New(shared)
		}
	}
	if deps.Config.Security.JWTAlgorithm.IsAsymmetric() {
		if core, err := security.NewTokenSigner(deps.Config.Security); err == nil && signer.SharesKeyWith(core) {
			return nil, errors.New(shared)
		}
	}
	return signer, nil
}

// validateSeedClients checks the parts of configured clients that do not
// need storage: identifiers and secrets. The rest is validated when they are
// written.
func validateSeedClients(clients []config.IDPClientConfig) error {
	seen := make(map[string]bool, len(clients))
	for i := range clients {
		client := &clients[i]
		if !validClientID(client.ClientID) {
			return fmt.Errorf("idp: Clients[%d]: ClientID %q must be 3 to 128 characters of letters, digits, '.', '_', '~' or '-'", i, client.ClientID)
		}
		if seen[client.ClientID] {
			return fmt.Errorf("idp: Clients: duplicate ClientID %q", client.ClientID)
		}
		seen[client.ClientID] = true
		switch {
		case client.Public && client.Secret != "":
			return fmt.Errorf("idp: Clients[%s]: a Public client has no Secret", client.ClientID)
		case !client.Public && len(client.Secret) < minClientSecretLength:
			return fmt.Errorf("idp: Clients[%s]: Secret must be at least %d characters (generate one with: openssl rand -hex 32), or set Public for an application that cannot keep a secret", client.ClientID, minClientSecretLength)
		}
	}
	return nil
}

func positiveOr(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

// validateServerURL checks an issuer or endpoint base: https, or http on a
// loopback host, or http anywhere when the host opted into insecure local
// development.
func validateServerURL(raw string, insecureAllowed bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%q must not contain a fragment", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%q must not contain credentials", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecureAllowed && !oauthproto.IsLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%q must use https (http is accepted on loopback hosts, or with Security.Session.AllowInsecureCookies for local development)", raw)
		}
	default:
		return nil, fmt.Errorf("%q must be an http or https URL", raw)
	}
	return u, nil
}

func validateFrontendURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q is not an absolute http or https URL", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%q must not contain a fragment", raw)
	}
	return nil
}
