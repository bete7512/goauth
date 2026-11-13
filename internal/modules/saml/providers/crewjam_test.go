package providers_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
)

// testIdP is a crewjam IdentityProvider that answers every AuthnRequest with
// a fixed session, which lets the adapter be exercised against real signed
// responses without an external IdP.
type testIdP struct {
	idp     *saml.IdentityProvider
	spMeta  *saml.EntityDescriptor
	session *saml.Session
}

func (t *testIdP) GetServiceProvider(_ *http.Request, _ string) (*saml.EntityDescriptor, error) {
	return t.spMeta, nil
}

func (t *testIdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return t.session
}

func keyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate, string, string) {
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
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return key, cert, certPEM, keyPEM
}

type fixture struct {
	provider  providers.ServiceProvider
	idp       *testIdP
	requestID string
	acsURL    string
	form      url.Values
}

func newFixture(t *testing.T, mutate func(*config.SAMLProviderConfig, *providers.SPOptions)) *fixture {
	t.Helper()
	idpKey, idpCert, _, _ := keyPair(t, "idp.example.com")
	_, _, spCertPEM, spKeyPEM := keyPair(t, "sp.example.com")

	idp := &saml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: mustURL("https://idp.example.com/metadata"),
		SSOURL:      mustURL("https://idp.example.com/sso"),
	}
	idpMetadata, err := xml.Marshal(idp.Metadata())
	require.NoError(t, err)

	spKey, spCert, err := providers.LoadKeyPair(spCertPEM, spKeyPEM)
	require.NoError(t, err)
	cfg := &config.SAMLProviderConfig{MetadataXML: string(idpMetadata), SignRequests: true}
	opts := providers.SPOptions{APIURL: "https://sp.example.com", BasePath: "/auth", Key: spKey, Certificate: spCert}
	if mutate != nil {
		mutate(cfg, &opts)
	}
	provider, err := providers.NewServiceProvider(context.Background(), "keycloak", cfg, opts)
	require.NoError(t, err)

	spMetaBytes, err := provider.Metadata()
	require.NoError(t, err)
	spMeta := &saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(spMetaBytes, spMeta))

	harness := &testIdP{idp: idp, spMeta: spMeta, session: &saml.Session{
		ID:               "session-1",
		CreateTime:       time.Now(),
		ExpireTime:       time.Now().Add(time.Hour),
		Index:            "idx-1",
		NameID:           "user-123",
		NameIDFormat:     providers.PersistentNameIDFormat,
		UserName:         "alice",
		UserEmail:        "Alice@Example.com",
		UserGivenName:    "Alice",
		UserSurname:      "Liddell",
		CustomAttributes: []saml.Attribute{{Name: "groups", Values: []saml.AttributeValue{{Value: "admins"}, {Value: "devs"}}}},
	}}
	idp.ServiceProviderProvider = harness
	idp.SessionProvider = harness

	redirectURL, requestID, err := provider.AuthnRequest(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, requestID)

	// Drive the IdP with the redirect the browser would follow.
	rec := httptest.NewRecorder()
	idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	form := url.Values{}
	for _, field := range []string{"SAMLResponse", "RelayState"} {
		re := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`)
		match := re.FindStringSubmatch(rec.Body.String())
		require.Len(t, match, 2, "form field %s missing in %s", field, rec.Body.String())
		form.Set(field, html.UnescapeString(match[1]))
	}
	require.Equal(t, requestID, form.Get("RelayState"))

	return &fixture{provider: provider, idp: harness, requestID: requestID, acsURL: "https://sp.example.com/auth/saml/keycloak/acs", form: form}
}

func (f *fixture) post(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, f.acsURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func mustURL(raw string) url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return *u
}

func TestRoundTripAcceptsSignedResponse(t *testing.T) {
	f := newFixture(t, nil)

	identity, err := f.provider.ParseResponse(f.post(f.form), []string{f.requestID})
	require.NoError(t, err)
	require.Equal(t, "user-123", identity.NameID)
	require.Equal(t, providers.PersistentNameIDFormat, identity.NameIDFormat)
	require.True(t, identity.IsPersistent())
	require.Equal(t, "https://idp.example.com/metadata", identity.Issuer)
	require.Equal(t, "idx-1", identity.SessionIndex)
	require.Equal(t, "alice@example.com", identity.Email)
	require.Equal(t, "Alice", identity.FirstName)
	require.Equal(t, "Liddell", identity.LastName)
	require.Equal(t, "alice", identity.Username)
	require.Equal(t, []string{"admins", "devs"}, identity.Groups)
	require.Equal(t, "https://idp.example.com/metadata", f.provider.IssuerEntityID())
}

func TestRoundTripRejectsUnknownRequestID(t *testing.T) {
	f := newFixture(t, nil)
	_, err := f.provider.ParseResponse(f.post(f.form), []string{"id-someone-else"})
	require.Error(t, err)
	// IdP-initiated acceptance is off, so an empty list is refused as well.
	_, err = f.provider.ParseResponse(f.post(f.form), nil)
	require.Error(t, err)
}

func TestRoundTripRejectsTamperedResponse(t *testing.T) {
	f := newFixture(t, nil)
	raw, err := base64.StdEncoding.DecodeString(f.form.Get("SAMLResponse"))
	require.NoError(t, err)
	// The assertion is encrypted, so tamper with the signed envelope instead.
	tampered := strings.Replace(string(raw), `Destination="https://sp.example.com`, `Destination="https://evil.example.com`, 1)
	require.NotEqual(t, string(raw), tampered)
	form := url.Values{}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tampered)))
	form.Set("RelayState", f.form.Get("RelayState"))

	_, err = f.provider.ParseResponse(f.post(form), []string{f.requestID})
	require.Error(t, err)
}

func TestMetadataAdvertisesACSAndCertificate(t *testing.T) {
	f := newFixture(t, nil)
	out, err := f.provider.Metadata()
	require.NoError(t, err)
	body := string(out)
	require.Contains(t, body, `entityID="https://sp.example.com/auth/saml/keycloak/metadata"`)
	require.Contains(t, body, `Location="https://sp.example.com/auth/saml/keycloak/acs"`)
	require.Contains(t, body, "<X509Certificate")
	require.Contains(t, body, `use="encryption"`)
	require.Contains(t, body, `AuthnRequestsSigned="true"`)
}

func TestNewServiceProviderValidation(t *testing.T) {
	ctx := context.Background()
	opts := providers.SPOptions{APIURL: "https://sp.example.com", BasePath: "/auth"}

	_, err := providers.NewServiceProvider(ctx, "Bad Name", &config.SAMLProviderConfig{MetadataXML: "<x/>"}, opts)
	require.ErrorContains(t, err, "invalid connection name")

	_, err = providers.NewServiceProvider(ctx, "idp", &config.SAMLProviderConfig{}, opts)
	require.ErrorContains(t, err, "MetadataURL or MetadataXML is required")

	_, err = providers.NewServiceProvider(ctx, "idp", &config.SAMLProviderConfig{MetadataXML: "<x/>", MetadataURL: "https://a"}, opts)
	require.ErrorContains(t, err, "not both")

	_, err = providers.NewServiceProvider(ctx, "idp", &config.SAMLProviderConfig{MetadataXML: "<x/>"}, providers.SPOptions{})
	require.ErrorContains(t, err, "APIURL is required")

	_, err = providers.NewServiceProvider(ctx, "idp", &config.SAMLProviderConfig{MetadataXML: "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"/>"}, opts)
	require.ErrorContains(t, err, "no IDPSSODescriptor")

	f := newFixture(t, nil)
	meta, err := f.provider.Metadata()
	require.NoError(t, err)
	_ = meta
	_, _, certPEM, _ := keyPair(t, "sp")
	_, _, err = providers.LoadKeyPair(certPEM, "")
	require.ErrorContains(t, err, "must be set together")
	_, _, _, otherKeyPEM := keyPair(t, "other")
	_, _, err = providers.LoadKeyPair(certPEM, otherKeyPEM)
	require.ErrorContains(t, err, "does not match")
}

func TestSignRequestsNeedsKey(t *testing.T) {
	idpKey, idpCert, _, _ := keyPair(t, "idp")
	idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: mustURL("https://idp/metadata"), SSOURL: mustURL("https://idp/sso")}
	md, err := xml.Marshal(idp.Metadata())
	require.NoError(t, err)
	_, err = providers.NewServiceProvider(context.Background(), "idp", &config.SAMLProviderConfig{MetadataXML: string(md), SignRequests: true}, providers.SPOptions{APIURL: "https://sp"})
	require.ErrorContains(t, err, "SignRequests needs SPCertificate and SPPrivateKey")
}

func TestMetadataURLIsFetched(t *testing.T) {
	idpKey, idpCert, _, _ := keyPair(t, "idp")
	idp := &saml.IdentityProvider{Key: idpKey, Certificate: idpCert, MetadataURL: mustURL("https://idp/metadata"), SSOURL: mustURL("https://idp/sso")}
	md, err := xml.Marshal(idp.Metadata())
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(md)
	}))
	defer server.Close()

	provider, err := providers.NewServiceProvider(context.Background(), "idp", &config.SAMLProviderConfig{MetadataURL: server.URL}, providers.SPOptions{APIURL: "https://sp", HTTPClient: server.Client()})
	require.NoError(t, err)
	require.Equal(t, "https://idp/metadata", provider.IssuerEntityID())
	require.False(t, provider.AllowIDPInitiated())
}
