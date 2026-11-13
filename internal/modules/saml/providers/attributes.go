package providers

import (
	"strings"

	"github.com/bete7512/goauth/pkg/config"
)

// NameID format URNs.
const (
	PersistentNameIDFormat   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	TransientNameIDFormat    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	EmailAddressNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	UnspecifiedNameIDFormat  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// NameIDFormatURN maps the short names accepted in configuration to URNs.
// An unknown value is returned unchanged so a full URN can be configured.
func NameIDFormatURN(short string) string {
	switch strings.ToLower(strings.TrimSpace(short)) {
	case "", "persistent":
		return PersistentNameIDFormat
	case "transient":
		return TransientNameIDFormat
	case "email", "emailaddress", "email_address":
		return EmailAddressNameIDFormat
	case "unspecified":
		return UnspecifiedNameIDFormat
	}
	return short
}

// Fallback attribute names, in priority order, for IdPs that use plain names
// (Keycloak user property mappers), LDAP OIDs (Keycloak X500 mappers,
// Shibboleth) or WS-Fed claim URIs (Entra ID, ADFS).
var (
	emailAttributes = []string{
		"email", "mail", "emailAddress", "Email",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"urn:oid:1.2.840.113549.1.9.1",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	}
	firstNameAttributes = []string{
		"firstName", "givenName", "given_name", "FirstName",
		"urn:oid:2.5.4.42",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
	}
	lastNameAttributes = []string{
		"lastName", "surname", "sn", "family_name", "LastName",
		"urn:oid:2.5.4.4",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
	}
	nameAttributes = []string{
		"name", "displayName", "cn", "commonName",
		"urn:oid:2.16.840.1.113730.3.1.241",
		"urn:oid:2.5.4.3",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	}
	usernameAttributes = []string{
		"username", "uid", "preferred_username",
		"urn:oid:0.9.2342.19200300.100.1.1",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
	}
	groupsAttributes = []string{
		"groups", "Role", "roles", "member", "memberOf",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
	}
)

// MapAttributes fills the user fields of identity from its Attributes using
// the configured mapping first and the built-in fallbacks second. When no
// email attribute is released but the NameID is an email address, the NameID
// is used as the email.
func MapAttributes(identity *Identity, mapping config.SAMLAttributeMapping) {
	identity.Email = first(identity.Attributes, mapping.Email, emailAttributes)
	identity.FirstName = first(identity.Attributes, mapping.FirstName, firstNameAttributes)
	identity.LastName = first(identity.Attributes, mapping.LastName, lastNameAttributes)
	identity.Name = first(identity.Attributes, mapping.Name, nameAttributes)
	identity.Username = first(identity.Attributes, mapping.Username, usernameAttributes)
	identity.Groups = all(identity.Attributes, mapping.Groups, groupsAttributes)

	if identity.Email == "" && identity.NameIDFormat == EmailAddressNameIDFormat {
		identity.Email = identity.NameID
	}
	identity.Email = strings.ToLower(strings.TrimSpace(identity.Email))
	if identity.Name == "" {
		identity.Name = strings.TrimSpace(identity.FirstName + " " + identity.LastName)
	}
}

func first(attrs map[string][]string, configured string, fallbacks []string) string {
	for _, value := range all(attrs, configured, fallbacks) {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func all(attrs map[string][]string, configured string, fallbacks []string) []string {
	if configured != "" {
		return attrs[configured]
	}
	for _, name := range fallbacks {
		if values, ok := attrs[name]; ok && len(values) > 0 {
			return values
		}
	}
	return nil
}
