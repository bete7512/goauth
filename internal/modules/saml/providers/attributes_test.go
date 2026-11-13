package providers_test

import (
	"testing"

	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestMapAttributesFallbacks(t *testing.T) {
	identity := &providers.Identity{Attributes: map[string][]string{
		"urn:oid:1.2.840.113549.1.9.1": {" Bob@Example.org "},
		"urn:oid:2.5.4.42":             {"Bob"},
		"urn:oid:2.5.4.4":              {"Builder"},
		"Role":                         {"admin", "dev"},
	}}
	providers.MapAttributes(identity, config.SAMLAttributeMapping{})
	require.Equal(t, "bob@example.org", identity.Email)
	require.Equal(t, "Bob", identity.FirstName)
	require.Equal(t, "Builder", identity.LastName)
	require.Equal(t, "Bob Builder", identity.Name)
	require.Equal(t, []string{"admin", "dev"}, identity.Groups)
}

func TestMapAttributesConfiguredNamesWin(t *testing.T) {
	identity := &providers.Identity{Attributes: map[string][]string{
		"email":       {"fallback@example.org"},
		"workEmail":   {"configured@example.org"},
		"displayName": {"Display"},
	}}
	providers.MapAttributes(identity, config.SAMLAttributeMapping{Email: "workEmail", Name: "missing"})
	require.Equal(t, "configured@example.org", identity.Email)
	require.Equal(t, "", identity.Name, "a configured attribute that is absent is not replaced by a fallback")
}

func TestMapAttributesEmailNameID(t *testing.T) {
	identity := &providers.Identity{NameID: "Carol@Example.com", NameIDFormat: providers.EmailAddressNameIDFormat, Attributes: map[string][]string{}}
	providers.MapAttributes(identity, config.SAMLAttributeMapping{})
	require.Equal(t, "carol@example.com", identity.Email)
	require.True(t, identity.IsPersistent())

	transient := &providers.Identity{NameID: "_abc", NameIDFormat: providers.TransientNameIDFormat}
	require.False(t, transient.IsPersistent())
}

func TestNameIDFormatURN(t *testing.T) {
	require.Equal(t, providers.PersistentNameIDFormat, providers.NameIDFormatURN(""))
	require.Equal(t, providers.PersistentNameIDFormat, providers.NameIDFormatURN("persistent"))
	require.Equal(t, providers.EmailAddressNameIDFormat, providers.NameIDFormatURN("email"))
	require.Equal(t, providers.TransientNameIDFormat, providers.NameIDFormatURN("transient"))
	require.Equal(t, providers.UnspecifiedNameIDFormat, providers.NameIDFormatURN("unspecified"))
	require.Equal(t, "urn:custom", providers.NameIDFormatURN("urn:custom"))
}

func TestRegistry(t *testing.T) {
	require.True(t, providers.ValidConnectionID("keycloak-prod_1"))
	require.False(t, providers.ValidConnectionID("Keycloak"))
	require.False(t, providers.ValidConnectionID("a/b"))
	require.False(t, providers.ValidConnectionID(""))
	r := providers.NewRegistry()
	require.Error(t, r.Register(nil))
	require.Equal(t, 0, r.Count())
	require.Empty(t, r.List())
}
