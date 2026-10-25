package providers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMicrosoftIDTokenEmailVerification(t *testing.T) {
	p := &MicrosoftProvider{}
	cases := []struct {
		name   string
		claims map[string]interface{}
		want   bool
	}{
		{"no verification signal", map[string]interface{}{"sub": "s", "email": "a@contoso.com"}, false},
		{"xms_edov true", map[string]interface{}{"sub": "s", "email": "a@contoso.com", "xms_edov": true}, true},
		{"xms_edov string", map[string]interface{}{"sub": "s", "email": "a@contoso.com", "xms_edov": "1"}, true},
		{"xms_edov false", map[string]interface{}{"sub": "s", "email": "a@contoso.com", "xms_edov": false}, false},
		{"explicit email_verified wins", map[string]interface{}{"sub": "s", "email": "a@contoso.com", "email_verified": false, "xms_edov": true}, false},
		{"email_verified true", map[string]interface{}{"sub": "s", "email": "a@contoso.com", "email_verified": true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, p.parseIDTokenClaims(tc.claims).EmailVerified)
		})
	}
}
