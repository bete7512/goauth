package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

// SPOptions carries the values shared by every connection of one GoAuth instance.
type SPOptions struct {
	// APIURL and BasePath build the ACS and metadata URLs: {APIURL}{BasePath}/saml/{name}/...
	APIURL   string
	BasePath string
	// Key and Certificate are the SP signing/decryption key pair; both may be nil.
	Key         crypto.Signer
	Certificate *x509.Certificate
	// HTTPClient fetches IdP metadata; nil uses a 15 second timeout client.
	HTTPClient *http.Client
}

// LoadKeyPair parses PEM-encoded certificate and private key. Both empty returns nil, nil, nil.
func LoadKeyPair(certPEM, keyPEM string) (crypto.Signer, *x509.Certificate, error) {
	certPEM, keyPEM = strings.TrimSpace(certPEM), strings.TrimSpace(keyPEM)
	if certPEM == "" && keyPEM == "" {
		return nil, nil, nil
	}
	if certPEM == "" || keyPEM == "" {
		return nil, nil, errors.New("saml: SPCertificate and SPPrivateKey must be set together")
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, errors.New("saml: SPCertificate is not PEM encoded")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("saml: parse SPCertificate: %w", err)
	}
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, nil, errors.New("saml: SPPrivateKey is not PEM encoded")
	}
	key, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("saml: parse SPPrivateKey: %w", err)
	}
	if !publicKeysMatch(cert.PublicKey, key.Public()) {
		return nil, nil, errors.New("saml: SPPrivateKey does not match SPCertificate")
	}
	return key, cert, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported key type")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("expected PKCS#8, PKCS#1 or EC private key")
}

func publicKeysMatch(certKey, signerKey crypto.PublicKey) bool {
	switch k := certKey.(type) {
	case *rsa.PublicKey:
		other, ok := signerKey.(*rsa.PublicKey)
		return ok && k.Equal(other)
	case *ecdsa.PublicKey:
		other, ok := signerKey.(*ecdsa.PublicKey)
		return ok && k.Equal(other)
	}
	return false
}

// crewjamProvider implements ServiceProvider on top of github.com/crewjam/saml.
type crewjamProvider struct {
	name              string
	sp                *saml.ServiceProvider
	issuer            string
	allowIDPInitiated bool
	mapping           config.SAMLAttributeMapping
}

// NewServiceProvider builds a connection from its configuration. IdP metadata
// is loaded here, so Init fails loudly when the IdP is unreachable or the
// document is not an IdP descriptor.
func NewServiceProvider(ctx context.Context, name string, cfg *config.SAMLProviderConfig, opts SPOptions) (ServiceProvider, error) {
	if !ValidConnectionID(name) {
		return nil, fmt.Errorf("saml: invalid connection name %q", name)
	}
	if cfg == nil {
		return nil, fmt.Errorf("saml: connection %q has no configuration", name)
	}
	if opts.APIURL == "" {
		return nil, errors.New("saml: APIURL is required to build the ACS URL")
	}
	base := strings.TrimRight(opts.APIURL, "/") + opts.BasePath + "/saml/" + name
	acsURL, err := url.Parse(base + "/acs")
	if err != nil {
		return nil, fmt.Errorf("saml: invalid ACS URL for %q: %w", name, err)
	}
	metadataURL, err := url.Parse(base + "/metadata")
	if err != nil {
		return nil, fmt.Errorf("saml: invalid metadata URL for %q: %w", name, err)
	}

	idpMetadata, err := loadIDPMetadata(ctx, cfg, opts.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("saml: connection %q: %w", name, err)
	}
	if len(idpMetadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("saml: connection %q: metadata has no IDPSSODescriptor", name)
	}

	sp := &saml.ServiceProvider{
		EntityID:          cfg.EntityID,
		Key:               opts.Key,
		Certificate:       opts.Certificate,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		IDPMetadata:       idpMetadata,
		AuthnNameIDFormat: saml.NameIDFormat(NameIDFormatURN(cfg.NameIDFormat)),
		AllowIDPInitiated: cfg.AllowIDPInitiated,
	}
	if cfg.SignRequests {
		if opts.Key == nil {
			return nil, fmt.Errorf("saml: connection %q: SignRequests needs SPCertificate and SPPrivateKey", name)
		}
		switch opts.Key.Public().(type) {
		case *rsa.PublicKey:
			sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		case *ecdsa.PublicKey:
			sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		default:
			return nil, fmt.Errorf("saml: connection %q: unsupported signing key type", name)
		}
	}
	if sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return nil, fmt.Errorf("saml: connection %q: IdP metadata has no HTTP-Redirect SingleSignOnService", name)
	}

	return &crewjamProvider{
		name:              name,
		sp:                sp,
		issuer:            idpMetadata.EntityID,
		allowIDPInitiated: cfg.AllowIDPInitiated,
		mapping:           cfg.Attributes,
	}, nil
}

func loadIDPMetadata(ctx context.Context, cfg *config.SAMLProviderConfig, client *http.Client) (*saml.EntityDescriptor, error) {
	switch {
	case cfg.MetadataXML != "" && cfg.MetadataURL != "":
		return nil, errors.New("set either MetadataURL or MetadataXML, not both")
	case cfg.MetadataXML != "":
		descriptor, err := samlsp.ParseMetadata([]byte(cfg.MetadataXML))
		if err != nil {
			return nil, fmt.Errorf("parse MetadataXML: %w", err)
		}
		return descriptor, nil
	case cfg.MetadataURL != "":
		target, err := url.Parse(cfg.MetadataURL)
		if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
			return nil, fmt.Errorf("MetadataURL %q is not an http(s) URL", cfg.MetadataURL)
		}
		if client == nil {
			client = &http.Client{Timeout: 15 * time.Second}
		}
		descriptor, err := samlsp.FetchMetadata(ctx, client, *target)
		if err != nil {
			return nil, fmt.Errorf("fetch IdP metadata from %s: %w", cfg.MetadataURL, err)
		}
		return descriptor, nil
	}
	return nil, errors.New("MetadataURL or MetadataXML is required")
}

func (p *crewjamProvider) Name() string            { return p.name }
func (p *crewjamProvider) IssuerEntityID() string  { return p.issuer }
func (p *crewjamProvider) AllowIDPInitiated() bool { return p.allowIDPInitiated }

// AuthnRequest builds a redirect-binding request. The request is signed as a
// query string when SignRequests is on, as the binding requires.
func (p *crewjamProvider) AuthnRequest(_ context.Context) (string, string, error) {
	req, err := p.sp.MakeAuthenticationRequest(p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	target, err := req.Redirect(req.ID, p.sp)
	if err != nil {
		return "", "", err
	}
	return target.String(), req.ID, nil
}

// ParseResponse verifies the POSTed SAMLResponse and maps the assertion.
func (p *crewjamProvider) ParseResponse(r *http.Request, possibleRequestIDs []string) (*Identity, error) {
	if r.PostForm == nil {
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("parse form: %w", err)
		}
	}
	assertion, err := p.sp.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) && invalid.PrivateErr != nil {
			return nil, invalid.PrivateErr
		}
		return nil, err
	}
	return identityFromAssertion(assertion, p.mapping), nil
}

func identityFromAssertion(assertion *saml.Assertion, mapping config.SAMLAttributeMapping) *Identity {
	identity := &Identity{Issuer: assertion.Issuer.Value, Attributes: map[string][]string{}}
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		identity.NameID = strings.TrimSpace(assertion.Subject.NameID.Value)
		identity.NameIDFormat = assertion.Subject.NameID.Format
		if identity.NameIDFormat == "" {
			identity.NameIDFormat = UnspecifiedNameIDFormat
		}
	}
	if len(assertion.AuthnStatements) > 0 {
		identity.SessionIndex = assertion.AuthnStatements[0].SessionIndex
	}
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				if v.Nil {
					continue
				}
				if v.NameID != nil && v.Value == "" {
					values = append(values, v.NameID.Value)
					continue
				}
				values = append(values, v.Value)
			}
			if attr.Name != "" {
				identity.Attributes[attr.Name] = append(identity.Attributes[attr.Name], values...)
			}
			if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
				identity.Attributes[attr.FriendlyName] = append(identity.Attributes[attr.FriendlyName], values...)
			}
		}
	}
	MapAttributes(identity, mapping)
	return identity
}

// Metadata renders the SP metadata document the IdP imports.
func (p *crewjamProvider) Metadata() ([]byte, error) {
	out, err := xml.MarshalIndent(p.sp.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}
