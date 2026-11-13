//go:build integration

package testhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/saml"
	crewjam "github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

// FakeSAMLIdP is an in-process SAML identity provider (crewjam's reference
// implementation) that signs in a fixed Session for every AuthnRequest.
type FakeSAMLIdP struct {
	IDP      *crewjam.IdentityProvider
	Session  *crewjam.Session
	spMeta   *crewjam.EntityDescriptor
	Metadata string
}

func (f *FakeSAMLIdP) GetServiceProvider(_ *http.Request, _ string) (*crewjam.EntityDescriptor, error) {
	return f.spMeta, nil
}

func (f *FakeSAMLIdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *crewjam.IdpAuthnRequest) *crewjam.Session {
	return f.Session
}

// SetSPMetadata tells the IdP which SP it is talking to, from the metadata document GoAuth serves.
func (f *FakeSAMLIdP) SetSPMetadata(t *testing.T, document []byte) {
	t.Helper()
	meta := &crewjam.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(document, meta))
	f.spMeta = meta
}

// Respond follows the SP's redirect to the IdP and returns the SAMLResponse
// and RelayState the IdP would have the browser post to the ACS.
func (f *FakeSAMLIdP) Respond(t *testing.T, redirectURL string) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	f.IDP.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	require.Equal(t, http.StatusOK, rec.Code, "idp sso: %s", rec.Body.String())
	form := url.Values{}
	for _, field := range []string{"SAMLResponse", "RelayState"} {
		match := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`).FindStringSubmatch(rec.Body.String())
		require.Len(t, match, 2, "form field %s missing", field)
		form.Set(field, html.UnescapeString(match[1]))
	}
	return form
}

// NewFakeSAMLIdP creates the IdP with a fresh key pair and default session.
func NewFakeSAMLIdP(t *testing.T) *FakeSAMLIdP {
	t.Helper()
	key, cert, _, _ := SAMLKeyPair(t, "idp.example.com")
	idp := &crewjam.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustParseURL("https://idp.example.com/metadata"),
		SSOURL:      mustParseURL("https://idp.example.com/sso"),
	}
	metadata, err := xml.Marshal(idp.Metadata())
	require.NoError(t, err)
	fake := &FakeSAMLIdP{IDP: idp, Metadata: string(metadata), Session: &crewjam.Session{
		ID:            "idp-session",
		CreateTime:    time.Now(),
		ExpireTime:    time.Now().Add(time.Hour),
		Index:         "idx",
		NameID:        "saml-subject-1",
		NameIDFormat:  string(crewjam.PersistentNameIDFormat),
		UserName:      "alice",
		UserEmail:     "alice@example.com",
		UserGivenName: "Alice",
		UserSurname:   "Liddell",
	}}
	idp.ServiceProviderProvider = fake
	idp.SessionProvider = fake
	return fake
}

// SAMLKeyPair generates a self-signed RSA certificate and returns it with PEM encodings.
func SAMLKeyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)}))
	return key, cert, certPEM, keyPEM
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

func mustParseURL(raw string) url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return *u
}

// SetupStatelessWithSAML creates a stateless auth instance with the oauth
// module (for the accounts table) and a SAML connection named "keycloak"
// pointing at the fake IdP.
func SetupStatelessWithSAML(t *testing.T, idp *FakeSAMLIdP, mutate func(*config.SAMLModuleConfig)) (*auth.Auth, http.Handler) {
	t.Helper()
	_, _, spCert, spKey := SAMLKeyPair(t, "sp.example.com")
	authInstance, err := auth.New(&config.Config{
		Storage:   newStore(t),
		BasePath:  "/auth",
		APIURL:    "http://localhost:8080",
		Security:  defaultSecurityConfig("saml-test-secret-key-32charslong", "saml-test-encryption-key-32char!"),
		Core:      &config.CoreConfig{RequireEmailVerification: false},
		RateLimit: &config.RateLimitModuleConfig{Disabled: true},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)

	samlCfg := &config.SAMLModuleConfig{
		SPCertificate: spCert,
		SPPrivateKey:  spKey,
		Providers: map[string]*config.SAMLProviderConfig{
			"keycloak": {MetadataXML: idp.Metadata, SignRequests: true},
		},
		AllowSignup: true,
		TrustEmail:  true,
	}
	if mutate != nil {
		mutate(samlCfg)
	}
	require.NoError(t, authInstance.Use(oauth.New(nil)))
	require.NoError(t, authInstance.Use(saml.New(samlCfg)))
	handler := initAuth(t, authInstance)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/saml/keycloak/metadata", nil))
	require.Equal(t, http.StatusOK, rec.Code, "sp metadata: %s", rec.Body.String())
	idp.SetSPMetadata(t, rec.Body.Bytes())
	return authInstance, handler
}
