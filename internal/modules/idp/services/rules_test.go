package services

import (
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

func validInput() *clientInput {
	return &clientInput{Name: "Dashboard", RedirectURIs: []string{"https://dashboard.example.com/callback"}, RequirePKCE: true}
}

func TestClientInputNormalize(t *testing.T) {
	in := &clientInput{
		Name:         "  Dashboard  ",
		RedirectURIs: []string{"https://dashboard.example.com/callback", "https://dashboard.example.com/callback", "http://127.0.0.1/cb", "com.example.app:/callback"},
		Scopes:       []string{"offline_access", "email", "openid", "email"},
		LogoURI:      " https://dashboard.example.com/logo.png ",
	}
	require.NoError(t, in.normalize())
	require.Equal(t, "Dashboard", in.Name)
	require.Equal(t, []string{"https://dashboard.example.com/callback", "http://127.0.0.1/cb", "com.example.app:/callback"}, in.RedirectURIs, "duplicates are dropped, order kept")
	require.Equal(t, []string{"openid", "email", "offline_access"}, in.Scopes, "scopes are stored in the advertised order")
	require.Equal(t, "https://dashboard.example.com/logo.png", in.LogoURI)

	defaults := validInput()
	require.NoError(t, defaults.normalize())
	require.Equal(t, []string{"openid", "profile", "email"}, defaults.Scopes)

	public := validInput()
	public.Public, public.RequirePKCE = true, false
	require.NoError(t, public.normalize())
	require.True(t, public.RequirePKCE, "a public client always requires PKCE")

	confidential := validInput()
	confidential.RequirePKCE = false
	require.NoError(t, confidential.normalize())
	require.False(t, confidential.RequirePKCE, "a confidential client may be allowed to go without")
}

func TestClientInputNormalizeRejects(t *testing.T) {
	many := make([]string, maxRedirectURIs+1)
	for i := range many {
		many[i] = "https://dashboard.example.com/callback/" + strings.Repeat("a", i+1)
	}
	cases := map[string]struct {
		change func(*clientInput)
		want   string
	}{
		"empty name":           {func(in *clientInput) { in.Name = "   " }, "name is required"},
		"long name":            {func(in *clientInput) { in.Name = strings.Repeat("n", maxClientNameLength+1) }, "at most"},
		"control char in name": {func(in *clientInput) { in.Name = "Dash\nboard" }, "control characters"},
		"no redirect":          {func(in *clientInput) { in.RedirectURIs = nil }, "at least one redirect URI"},
		"too many redirects":   {func(in *clientInput) { in.RedirectURIs = many }, "at most"},
		"http redirect":        {func(in *clientInput) { in.RedirectURIs = []string{"http://dashboard.example.com/cb"} }, "loopback"},
		"relative redirect":    {func(in *clientInput) { in.RedirectURIs = []string{"/callback"} }, "absolute"},
		"redirect fragment":    {func(in *clientInput) { in.RedirectURIs = []string{"https://dashboard.example.com/cb#f"} }, "fragment"},
		"redirect credentials": {func(in *clientInput) { in.RedirectURIs = []string{"https://user:pw@dashboard.example.com/cb"} }, "credentials"},
		"javascript redirect":  {func(in *clientInput) { in.RedirectURIs = []string{"javascript:alert(1)"} }, "not allowed"},
		"unknown scope":        {func(in *clientInput) { in.Scopes = []string{"openid", "admin"} }, "not supported"},
		"no openid":            {func(in *clientInput) { in.Scopes = []string{"email"} }, "must include openid"},
		"logo scheme":          {func(in *clientInput) { in.LogoURI = "javascript:alert(1)" }, "logo_uri"},
		"relative client uri":  {func(in *clientInput) { in.ClientURI = "/about" }, "client_uri"},
		"client uri with user": {func(in *clientInput) { in.ClientURI = "https://a:b@dashboard.example.com" }, "client_uri"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := validInput()
			tc.change(in)
			require.ErrorContains(t, in.normalize(), tc.want)
		})
	}
}

func TestValidClientID(t *testing.T) {
	for _, id := range []string{"app", "grafana-prod", "a.b_c~d", "0198f0d2-7d3a-7c4e-9c1a-1f2e3d4c5b6a", strings.Repeat("a", 128)} {
		require.True(t, validClientID(id), id)
	}
	for _, id := range []string{"", "ab", "my app", "app:1", "app/1", "app@example.com", "ünïcode", strings.Repeat("a", 129)} {
		require.False(t, validClientID(id), id)
	}
}

func TestDecodeBasicCredentials(t *testing.T) {
	id, secret := DecodeBasicCredentials("my%20app", "p%40ss%2Bword+with+spaces")
	require.Equal(t, "my app", id)
	require.Equal(t, "p@ss+word with spaces", secret)

	// What is not form encoding is taken as it is.
	id, secret = DecodeBasicCredentials("app", "100%zz")
	require.Equal(t, "app", id)
	require.Equal(t, "100%zz", secret)
}

func TestUserClaims(t *testing.T) {
	updated := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	user := &models.User{
		ID: "user-1", Name: "Ada Lovelace", FirstName: "Ada", LastName: "Lovelace", Username: "ada", Avatar: "https://example.com/ada.png",
		Email: "ada@example.com", EmailVerified: true, PhoneNumber: "+251911000000", PasswordHash: "secret-hash",
		CreatedAt: updated.Add(-time.Hour), UpdatedAt: &updated,
	}

	require.Empty(t, userClaims(user, []string{ScopeOpenID}), "openid alone releases only the subject, which the caller sets")

	claims := userClaims(user, []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone})
	require.Equal(t, map[string]interface{}{
		"name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace", "preferred_username": "ada",
		"picture": "https://example.com/ada.png", "updated_at": updated.Unix(),
		"email": "ada@example.com", "email_verified": true,
		"phone_number": "+251911000000", "phone_number_verified": false,
	}, claims)
	for name, value := range claims {
		require.NotEqual(t, "secret-hash", value, name)
	}

	sparse := userClaims(&models.User{ID: "user-2", Email: "x@example.com"}, []string{ScopeProfile, ScopeEmail, ScopePhone})
	require.Equal(t, map[string]interface{}{"email": "x@example.com", "email_verified": false}, sparse, "empty values are left out")
}

func TestLoginStale(t *testing.T) {
	requestedAt := time.Date(2026, 11, 15, 10, 0, 0, 500_000_000, time.UTC)
	now := requestedAt.Add(30 * time.Second)
	age := func(seconds int64) *int64 { return &seconds }
	at := func(t time.Time) types.Principal { return types.Principal{UserID: "user-1", AuthenticatedAt: t} }

	cases := map[string]struct {
		pending   pendingAuthorization
		principal types.Principal
		stale     bool
	}{
		"nothing asked":                    {pendingAuthorization{}, at(requestedAt.Add(-time.Hour)), false},
		"nothing asked, unknown time":      {pendingAuthorization{}, types.Principal{UserID: "user-1"}, false},
		"login: signed in before":          {pendingAuthorization{RequireLogin: true}, at(requestedAt.Add(-2 * time.Second)), true},
		"login: signed in after":           {pendingAuthorization{RequireLogin: true}, at(requestedAt.Add(5 * time.Second)), false},
		"login: same second":               {pendingAuthorization{RequireLogin: true}, at(requestedAt.Truncate(time.Second)), false},
		"login: unknown time":              {pendingAuthorization{RequireLogin: true}, types.Principal{UserID: "user-1"}, true},
		"max_age: recent enough":           {pendingAuthorization{MaxAge: age(3600)}, at(now.Add(-10 * time.Minute)), false},
		"max_age: too old":                 {pendingAuthorization{MaxAge: age(300)}, at(now.Add(-10 * time.Minute)), true},
		"max_age: zero, signed in earlier": {pendingAuthorization{MaxAge: age(0)}, at(now.Add(-2 * time.Second)), true},
		"max_age: zero, signed in now":     {pendingAuthorization{MaxAge: age(0)}, at(now), false},
		"max_age: unknown time":            {pendingAuthorization{MaxAge: age(3600)}, types.Principal{UserID: "user-1"}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.stale, loginStale(&tc.pending, requestedAt, tc.principal, now))
		})
	}
}

func TestConsentRequired(t *testing.T) {
	client := &models.IDPClient{ClientID: "app"}
	firstParty := &models.IDPClient{ClientID: "ours", SkipConsent: true}
	grant := &models.IDPGrant{Scopes: models.StringList{"openid", "email"}}
	request := func(force bool, scopes ...string) *pendingAuthorization {
		return &pendingAuthorization{Scopes: scopes, ForceConsent: force}
	}

	require.True(t, consentRequired(client, request(false, "openid"), nil), "nothing approved yet")
	require.False(t, consentRequired(client, request(false, "openid", "email"), grant), "already approved")
	require.False(t, consentRequired(client, request(false, "openid"), grant), "less than approved")
	require.True(t, consentRequired(client, request(false, "openid", "profile"), grant), "more than approved")
	require.True(t, consentRequired(client, request(true, "openid"), grant), "the application insists")
	require.False(t, consentRequired(firstParty, request(false, "openid"), nil), "the host's own application")
	require.False(t, consentRequired(firstParty, request(true, "openid", "profile"), nil), "the host's own application, even when it insists")
}

// The example of OpenID Connect Core section A.3.
func TestAccessTokenHash(t *testing.T) {
	require.Equal(t, "77QmUPtjPfzWtF2AnpK9RQ", accessTokenHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"))
}

func TestCredentialBinding(t *testing.T) {
	user := &models.User{ID: "user-1", PasswordHash: "$2a$10$abcdefghijklmnopqrstuv"}
	binding := credentialBinding(user)
	require.Len(t, binding, 32)
	require.Equal(t, binding, credentialBinding(&models.User{ID: "another-user", PasswordHash: user.PasswordHash}), "it depends on the password alone")
	require.NotContains(t, binding, "abcdefghij", "it reveals nothing of the stored hash")

	changed := *user
	changed.PasswordHash = "$2a$10$zyxwvutsrqponmlkjihgfe"
	require.NotEqual(t, binding, credentialBinding(&changed), "a new password is a new binding")

	// Signing out bumps the token version and must leave the binding alone.
	signedOut := *user
	signedOut.TokenVersion++
	require.Equal(t, binding, credentialBinding(&signedOut))
}

func TestSupportedScopesAreDescribed(t *testing.T) {
	for _, scope := range supportedScopes {
		require.NotEmpty(t, scopeDescriptions[scope], "scope %s needs a description for the consent page", scope)
		require.True(t, supportedScope(scope))
	}
	require.False(t, supportedScope("admin"))
	for _, scope := range defaultClientScopes {
		require.True(t, supportedScope(scope))
	}
}
