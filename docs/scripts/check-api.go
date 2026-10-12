//go:build ignore

// Run through npm run check:api. This is a documentation verification tool,
// not part of the library. It uses temporary SQLite databases and no network.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/captcha"
	"github.com/bete7512/goauth/pkg/modules/csrf"
	"github.com/bete7512/goauth/pkg/modules/invitation"
	"github.com/bete7512/goauth/pkg/modules/magiclink"
	"github.com/bete7512/goauth/pkg/modules/notification"
	"github.com/bete7512/goauth/pkg/modules/oauth"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/passkeys"
	"github.com/bete7512/goauth/pkg/modules/session"
	"github.com/bete7512/goauth/pkg/modules/stateless"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
)

type route struct{ Method, Path, Name string }

func verify(dir, strategy string) ([]route, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := storage.NewGormStorage(storage.GormConfig{
		Dialect: types.DialectTypeSqlite,
		DSN:     filepath.Join(dir, strategy+".db"),
	})
	if err != nil {
		return nil, err
	}
	a, err := auth.New(&config.Config{
		Storage: store, APIURL: "http://localhost:8080", BasePath: "/auth",
		Core: &config.CoreConfig{},
		Migration: config.MigrationConfig{Auto: true},
		Security: types.SecurityConfig{
			JwtSecretKey:  strings.Repeat("d", 32),
			EncryptionKey: strings.Repeat("e", 32),
			AuthMode:      types.AuthModeBearer,
		},
	})
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	defer a.Close()
	var credentialModule config.Component = stateless.New(nil)
	if strategy == "session" {
		credentialModule = session.New(nil)
	}
	for _, module := range []config.Component{
		credentialModule, admin.New(nil), audit.New(nil), captcha.New(nil),
		// Exempt this fixture's JSON requests; the module still contributes its route.
		csrf.New(&config.CSRFModuleConfig{ExcludePaths: []string{"/auth/"}}),
		invitation.New(nil), magiclink.New(nil), notification.New(nil), oauth.New(nil),
		organization.New(nil), passkeys.New(&config.PasskeysModuleConfig{
			RPID: "localhost", RPOrigins: []string{"http://localhost:3000"},
		}), twofactor.New(nil),
	} {
		if err := a.Use(module); err != nil {
			return nil, err
		}
	}
	if err := a.Initialize(ctx); err != nil {
		return nil, err
	}
	routes := make([]route, 0, len(a.Routes()))
	for _, r := range a.Routes() {
		routes = append(routes, route{r.Method, strings.TrimPrefix(r.Path, "/auth"), r.Name})
	}
	mux := http.NewServeMux()
	stdhttp.Register(mux, a)
	request := func(method, path, body, token string, status int) (map[string]any, error) {
		req := httptest.NewRequest(method, "/auth"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != status {
			return nil, fmt.Errorf("%s %s: got %d, want %d: %s", method, path, rec.Code, status, rec.Body.String())
		}
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			return nil, err
		}
		return envelope.Data, nil
	}
	credentials := `{"email":"docs@example.com","password":"documentation-password","name":"Docs"}`
	data, err := request("POST", "/signup", credentials, "", 201)
	if err != nil {
		return nil, err
	}
	if data["access_token"] != nil || data["user"] == nil {
		return nil, fmt.Errorf("signup must return a user without credentials")
	}
	data, err = request("POST", "/login", credentials, "", 200)
	if err != nil {
		return nil, err
	}
	access, ok := data["access_token"].(string)
	if !ok || access == "" {
		return nil, fmt.Errorf("login missing access credential")
	}
	refresh, ok := data["refresh_token"].(string)
	if !ok || refresh == "" {
		return nil, fmt.Errorf("login missing refresh credential")
	}
	if _, err = request("GET", "/me", "", access, 200); err != nil {
		return nil, err
	}
	if _, err = request("GET", "/me", "", refresh, 401); err != nil {
		return nil, err
	}
	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": refresh})
	data, err = request("POST", "/refresh", string(refreshBody), "", 200)
	if err != nil {
		return nil, err
	}
	rotated, _ := data["refresh_token"].(string)
	if rotated == "" || rotated == refresh {
		return nil, fmt.Errorf("refresh did not rotate")
	}
	if _, err = request("POST", "/refresh", string(refreshBody), "", 401); err != nil {
		return nil, err
	}
	access, _ = data["access_token"].(string)
	if _, err = request("POST", "/logout", "", access, 200); err != nil {
		return nil, err
	}
	if _, err = request("GET", "/me", "", access, 401); err != nil {
		return nil, err
	}
	return routes, nil
}

func main() {
	dir, err := os.MkdirTemp("", "goauth-doc-api-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	var routes []route
	for _, strategy := range []string{"stateless", "session"} {
		found, err := verify(dir, strategy)
		if err != nil {
			fmt.Fprintln(os.Stderr, strategy+":", err)
			os.Exit(1)
		}
		routes = append(routes, found...)
	}
	output, err := json.Marshal(routes)
	if err != nil {
		panic(err)
	}
	fmt.Println("DOCS_API_JSON=" + string(output))
}
