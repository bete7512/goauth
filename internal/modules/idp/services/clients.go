package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

const (
	maxClientNameLength = 120
	maxRedirectURIs     = 20
	// clientTouchInterval bounds how often a client's last use is written.
	clientTouchInterval = time.Minute
)

// clientIDPattern is the form of a client_id: unreserved URL characters, so
// it needs no escaping in a query string or in HTTP Basic credentials.
var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{3,128}$`)

func validClientID(id string) bool {
	return clientIDPattern.MatchString(id)
}

// randomToken returns n random bytes as an unpadded base64url string.
func randomToken(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// clientSecretDigest returns the stored form of a client secret. A plain
// digest is enough because secrets are random or, when they come from
// configuration, at least 32 characters long.
func clientSecretDigest(secret string) string {
	return security.TokenDigest(secret)
}

// clientInput is a client registration before validation.
type clientInput struct {
	Name         string
	RedirectURIs []string
	Scopes       []string
	Public       bool
	RequirePKCE  bool
	SkipConsent  bool
	LogoURI      string
	ClientURI    string
	Disabled     bool
}

// normalize validates the registration and puts it in stored form. The error
// is a sentence for whoever registers the client.
func (in *clientInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return errors.New("name is required")
	}
	if len(in.Name) > maxClientNameLength {
		return fmt.Errorf("name must be at most %d characters", maxClientNameLength)
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) {
			return errors.New("name must not contain control characters")
		}
	}

	if len(in.RedirectURIs) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	if len(in.RedirectURIs) > maxRedirectURIs {
		return fmt.Errorf("at most %d redirect URIs are allowed", maxRedirectURIs)
	}
	seen := make(map[string]bool, len(in.RedirectURIs))
	redirects := make([]string, 0, len(in.RedirectURIs))
	for _, uri := range in.RedirectURIs {
		if err := oauthproto.ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("redirect URI %q: %w", uri, err)
		}
		if !seen[uri] {
			seen[uri] = true
			redirects = append(redirects, uri)
		}
	}
	in.RedirectURIs = redirects

	requested := in.Scopes
	if len(requested) == 0 {
		requested = defaultClientScopes
	}
	wanted := make(map[string]bool, len(requested))
	for _, scope := range requested {
		if !supportedScope(scope) {
			return fmt.Errorf("scope %q is not supported (supported: %s)", scope, strings.Join(supportedScopes, ", "))
		}
		wanted[scope] = true
	}
	if !wanted[ScopeOpenID] {
		return errors.New("scopes must include openid")
	}
	// Stored in the advertised order, whatever order they were given in.
	in.Scopes = make([]string, 0, len(wanted))
	for _, scope := range supportedScopes {
		if wanted[scope] {
			in.Scopes = append(in.Scopes, scope)
		}
	}

	// A public client proves it started the flow with PKCE and nothing else.
	if in.Public {
		in.RequirePKCE = true
	}
	var err error
	if in.LogoURI, err = informationalURI(in.LogoURI); err != nil {
		return fmt.Errorf("logo_uri %w", err)
	}
	if in.ClientURI, err = informationalURI(in.ClientURI); err != nil {
		return fmt.Errorf("client_uri %w", err)
	}
	return nil
}

// informationalURI validates an optional URI that is only shown to the user.
func informationalURI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > oauthproto.MaxURILength {
		return "", errors.New("is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return "", errors.New("must be an absolute http or https URL")
	}
	return raw, nil
}

// apply copies a validated registration onto a client.
func (in *clientInput) apply(client *models.IDPClient) {
	client.Name = in.Name
	client.RedirectURIs = append(models.StringList{}, in.RedirectURIs...)
	client.Scopes = append(models.StringList{}, in.Scopes...)
	client.Public = in.Public
	client.RequirePKCE = in.RequirePKCE
	client.SkipConsent = in.SkipConsent
	client.LogoURI = in.LogoURI
	client.ClientURI = in.ClientURI
	client.Disabled = in.Disabled
}

func clientDTO(client *models.IDPClient) dto.Client {
	return dto.Client{
		ID: client.ID, ClientID: client.ClientID, Name: client.Name, Public: client.Public,
		RedirectURIs: append([]string{}, client.RedirectURIs...), Scopes: append([]string{}, client.Scopes...),
		RequirePKCE: client.RequirePKCE, SkipConsent: client.SkipConsent, LogoURI: client.LogoURI, ClientURI: client.ClientURI,
		Managed: client.Managed, Disabled: client.Disabled, LastUsedAt: client.LastUsedAt,
		CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
	}
}

// resolveClient loads an enabled client by its public identifier. An unknown
// and a disabled client are answered alike.
func (s *idpService) resolveClient(ctx context.Context, clientID string) (*models.IDPClient, *types.GoAuthError) {
	if !validClientID(clientID) {
		return nil, errInvalidClient()
	}
	client, err := s.stores.Clients.FindByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, errInvalidClient()
		}
		return nil, errServer(err)
	}
	// Compared again here: a storage backend may match without regard to case.
	if client.ClientID != clientID || client.Disabled {
		return nil, errInvalidClient()
	}
	return client, nil
}

// authenticateClient identifies the client of a token request and checks its
// credentials: HTTP Basic (client_secret_basic), form fields
// (client_secret_post), or the client_id alone for a public client.
func (s *idpService) authenticateClient(ctx context.Context, req *TokenRequest) (*models.IDPClient, *types.GoAuthError) {
	formID, formSecret := req.Form.Get("client_id"), req.Form.Get("client_secret")
	var clientID, secret string
	presented := false
	switch {
	case req.HasBasic:
		// A request uses one authentication method (RFC 6749 section 2.3).
		if formSecret != "" {
			return nil, errInvalidRequest("Use only one client authentication method")
		}
		if formID != "" && formID != req.BasicID {
			return nil, errInvalidRequest("client_id does not match the authenticated client")
		}
		clientID, secret, presented = req.BasicID, req.BasicSecret, true
	case formSecret != "":
		clientID, secret, presented = formID, formSecret, true
	default:
		clientID = formID
	}
	if clientID == "" {
		return nil, errInvalidClient()
	}
	client, authErr := s.resolveClient(ctx, clientID)
	if authErr != nil {
		return nil, authErr
	}
	if client.Public {
		// A public client has no secret; one that sends a secret is not
		// the client it claims to be.
		if presented {
			return nil, errInvalidClient()
		}
		return client, nil
	}
	if !presented || client.SecretHash == "" {
		return nil, errInvalidClient()
	}
	if subtle.ConstantTimeCompare([]byte(clientSecretDigest(secret)), []byte(client.SecretHash)) != 1 {
		return nil, errInvalidClient()
	}
	return client, nil
}

// DecodeBasicCredentials undoes the form encoding that RFC 6749 section 2.3.1
// applies to a client_id and secret before they go into HTTP Basic. A value
// that is not valid form encoding is taken as it is.
func DecodeBasicCredentials(username, password string) (string, string) {
	if decoded, err := url.QueryUnescape(username); err == nil {
		username = decoded
	}
	if decoded, err := url.QueryUnescape(password); err == nil {
		password = decoded
	}
	return username, password
}

// touchClient records that the client obtained a token, at most once per
// clientTouchInterval.
func (s *idpService) touchClient(ctx context.Context, client *models.IDPClient) {
	now := s.now()
	if client.LastUsedAt != nil && now.Sub(*client.LastUsedAt) < clientTouchInterval {
		return
	}
	if err := s.stores.Clients.TouchLastUsed(ctx, client.ID, now); err != nil {
		s.logger.Warnf("idp: failed to record client use: %v", err)
	}
}
