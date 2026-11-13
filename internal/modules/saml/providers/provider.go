// Package providers wraps the SAML protocol behind a small interface so the
// service, handlers and tests never depend on the underlying SAML library.
package providers

import (
	"context"
	"net/http"
)

//go:generate mockgen -destination=../../../mocks/mock_saml_provider.go -package=mocks github.com/bete7512/goauth/internal/modules/saml/providers ServiceProvider

// ServiceProvider is one configured IdP connection, seen from the SP side.
// Implementations must verify the response completely (signature, audience,
// destination, time window, InResponseTo) before returning an Identity.
type ServiceProvider interface {
	// Name is the connection name used in URLs and stored on linked accounts.
	Name() string

	// IssuerEntityID is the entity ID of the identity provider.
	IssuerEntityID() string

	// AllowIDPInitiated reports whether unsolicited responses are accepted.
	AllowIDPInitiated() bool

	// AuthnRequest builds a SAML AuthnRequest for the HTTP-Redirect binding.
	// It returns the URL to send the browser to and the request ID, which is
	// also sent as RelayState so the IdP echoes it next to InResponseTo.
	AuthnRequest(ctx context.Context) (redirectURL string, requestID string, err error)

	// ParseResponse validates the SAMLResponse carried by an HTTP-POST binding
	// request. possibleRequestIDs lists the AuthnRequest IDs the response may
	// answer; an empty list is only valid when AllowIDPInitiated is on.
	ParseResponse(r *http.Request, possibleRequestIDs []string) (*Identity, error)

	// Metadata returns the SP metadata document for this connection.
	Metadata() ([]byte, error)
}

// Identity is what an assertion says about the user, already mapped onto
// GoAuth's user fields. NameID identifies the subject at the IdP.
type Identity struct {
	NameID       string
	NameIDFormat string
	Issuer       string
	SessionIndex string

	Email     string
	Username  string
	Name      string
	FirstName string
	LastName  string
	Groups    []string

	// Attributes holds every released attribute keyed by Name (and FriendlyName).
	Attributes map[string][]string
}

// IsPersistent reports whether NameID can identify the same user on a later login.
func (i *Identity) IsPersistent() bool {
	return i.NameID != "" && i.NameIDFormat != TransientNameIDFormat
}
