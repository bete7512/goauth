// Command idp is a runnable example of GoAuth as an OpenID Connect provider:
// another application signs users in with the accounts of this one.
//
// One process serves two things on http://localhost:8080:
//
//   - /auth/...      GoAuth: accounts, sign in, and the identity provider
//     (issuer http://localhost:8080/auth/oidc)
//   - /oidc/consent  the page where the user signs in and approves a client
//
// Run it from the examples directory and point an OpenID Connect client at
// the issuer:
//
//	go run ./idp
//
// The registered client is "demo-app". Its secret and redirect URIs come from
// CLIENT_SECRET and REDIRECT_URIS; the defaults fit Grafana on port 3000 and
// oauth2-proxy on port 4180. Set PORT to use another port.
//
// Everything is kept in memory and the signing key is generated at start, so
// the example forgets its users and grants when it stops, and ID tokens
// issued before a restart no longer verify.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
)

// The example serves everything from one origin. The issuer is a URL that
// clients compare character by character, so it is derived once from the
// port in use.
var (
	port   = envOr("PORT", "8080")
	origin = "http://localhost:" + port
	issuer = origin + "/auth/oidc"
)

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

//go:embed consent.html consent.js
var pages embed.FS

func main() {
	store, err := storage.NewGormStorage(storage.GormConfig{
		Dialect:  types.DialectTypeSqlite,
		DSN:      "file:goauth-idp-example?mode=memory&cache=shared",
		LogLevel: "silent",
	})
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	a, err := auth.New(&config.Config{
		Storage:   store,
		APIURL:    origin,
		BasePath:  "/auth",
		Core:      &config.CoreConfig{},
		Migration: config.MigrationConfig{Auto: true},
		Security: types.SecurityConfig{
			// Demo values. Load real secrets from the environment.
			JwtSecretKey:  "example-jwt-secret-change-me-32-chars",
			EncryptionKey: "example-encryption-key-change-me",
			// The consent page keeps the user's token in the tab and sends
			// it as a bearer token, so no cookies are involved.
			AuthMode: types.AuthModeBearer,
		},
	})
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	defer a.Close()

	// One client application may sign users in. A real host declares its
	// clients here, or turns on AdminAPI and registers them at runtime.
	clientSecret := envOr("CLIENT_SECRET", "example-client-secret-change-me-0123456789")
	provider := idp.New(&config.IDPModuleConfig{
		ConsentURL: origin + "/oidc/consent",
		// ID tokens are verified with a public key, so the module needs an
		// RSA key of its own. Keep yours stable across restarts.
		SigningKey: config.IDPSigningKey{PrivateKeyPEM: ephemeralSigningKey()},
		Clients: []config.IDPClientConfig{{
			ClientID:     "demo-app",
			Secret:       clientSecret,
			Name:         "Demo application",
			RedirectURIs: strings.Split(envOr("REDIRECT_URIS", "http://localhost:3000/login/generic_oauth,http://localhost:4180/oauth2/callback"), ","),
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
			// Most client software sends PKCE only when told to. Leave this
			// out to require it.
			AllowWithoutPKCE: os.Getenv("REQUIRE_PKCE") == "",
		}},
	})
	if err := a.Use(provider); err != nil {
		log.Fatalf("idp: %v", err)
	}
	if err := a.Initialize(context.Background()); err != nil {
		log.Fatalf("initialize: %v", err)
	}

	mux := http.NewServeMux()
	stdhttp.Register(mux, a)
	mux.HandleFunc("GET /oidc/consent", consentPage("consent.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /oidc/consent.js", consentPage("consent.js", "text/javascript; charset=utf-8"))

	log.Printf("Issuer:        %s", issuer)
	log.Printf("Discovery:     %s/.well-known/openid-configuration", issuer)
	log.Printf("Client ID:     demo-app")
	log.Printf("Consent page:  %s/oidc/consent", origin)
	log.Fatal(http.ListenAndServe("localhost:"+port, mux))
}

// ephemeralSigningKey creates an RSA key for this run of the example.
func ephemeralSigningKey() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// consentPage serves one file of the consent UI. The page decides who signs
// in to an application as whom, so it must never be framed by another site,
// and it runs no script but its own.
func consentPage(name, contentType string) http.HandlerFunc {
	body, err := pages.ReadFile(name)
	if err != nil {
		log.Fatalf("consent page: %v", err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		header := w.Header()
		header.Set("Content-Type", contentType)
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src https: data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}
