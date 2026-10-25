package config

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/types"
)

func validConfig() *Config {
	return &Config{
		Storage: &types.StorageSet{},
		Security: types.SecurityConfig{
			JwtSecretKey:  "config-test-secret-key-32-chars!!",
			EncryptionKey: "config-test-encryption-key-32c!!",
		},
	}
}

func TestValidateCookiesAreSecureByDefault(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.Session.Secure || !cfg.Security.Session.HttpOnly {
		t.Fatalf("default cookies must be Secure and HttpOnly: %+v", cfg.Security.Session)
	}
	if cfg.Security.Session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("default SameSite = %v, want Lax", cfg.Security.Session.SameSite)
	}
}

func TestValidateAllowInsecureCookiesIsExplicit(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Session.Secure = true // the deprecated field is overwritten
	cfg.Security.Session.AllowInsecureCookies = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Security.Session.Secure {
		t.Fatal("AllowInsecureCookies must drop the Secure attribute")
	}
}

func TestValidateRejectsSameSiteNoneWithoutSecure(t *testing.T) {
	cfg := validConfig()
	cfg.Security.Session.SameSite = http.SameSiteNoneMode
	cfg.Security.Session.AllowInsecureCookies = true
	err := cfg.Validate()
	if err == nil || !IsConfigErr(err) || !strings.Contains(err.Error(), "SameSite=None") {
		t.Fatalf("expected config error for SameSite=None without Secure, got %v", err)
	}
	cfg = validConfig()
	cfg.Security.Session.SameSite = http.SameSiteNoneMode
	if err := cfg.Validate(); err != nil {
		t.Fatalf("SameSite=None with secure cookies must be accepted: %v", err)
	}
}

func TestValidateRejectsBadTrustedProxies(t *testing.T) {
	cfg := validConfig()
	cfg.TrustedProxies = []string{"10.0.0.0/8", "not-an-address"}
	if err := cfg.Validate(); err == nil || !IsConfigErr(err) {
		t.Fatalf("expected config error, got %v", err)
	}
}
