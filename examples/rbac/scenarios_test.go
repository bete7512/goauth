package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/examples/rbac/internal/api"
	"github.com/bete7512/goauth/examples/rbac/internal/platform"
	"github.com/bete7512/goauth/examples/rbac/internal/seed"
	"github.com/bete7512/goauth/examples/rbac/internal/tracker"
	"github.com/google/uuid"
)

// The scenarios README.md walks through, run end to end: sign in as each
// person, then call the routes router.go guards.

type app struct {
	t       *testing.T
	handler http.Handler
	cast    *seed.Cast
}

func start(t *testing.T) *app {
	t.Helper()
	ctx := context.Background()
	p, err := platform.New(ctx, platform.Settings{
		Origin: "http://localhost:8080", JWTSecret: "rbac-example-jwt-secret-change-me-32", EncryptionKey: "rbac-example-encryption-key-32chr",
		DSN: "file:" + uuid.NewString() + "?mode=memory&cache=shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	mux := http.NewServeMux()
	handler := p.Mount(mux)
	store := tracker.NewStore()
	api.New(store, p.Authz, p.TeamOrg).Routes(mux, p.Auth.RequireAuth)
	cast, err := seed.Run(ctx, p, handler, store)
	if err != nil {
		t.Fatal(err)
	}
	return &app{t: t, handler: handler, cast: cast}
}

func (a *app) call(method, path, token string, body any) (int, map[string]any) {
	a.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// signIn returns a token for name, signed in to orgID when it is set.
func (a *app) signIn(name, orgID string) string {
	a.t.Helper()
	code, body := a.call("POST", "/auth/login", "", map[string]string{"email": a.cast.People[name].Email, "password": seed.Password})
	if code != http.StatusOK {
		a.t.Fatalf("login %s: %d %v", name, code, body)
	}
	token := body["data"].(map[string]any)["access_token"].(string)
	if orgID == "" {
		return token
	}
	code, body = a.call("POST", "/auth/org/switch", token, map[string]string{"org_id": orgID})
	if code != http.StatusOK {
		a.t.Fatalf("switch %s to %s: %d %v", name, orgID, code, body)
	}
	return body["data"].(map[string]any)["access_token"].(string)
}

func (a *app) expect(who, method, path, token string, body any, want int) {
	a.t.Helper()
	if code, out := a.call(method, path, token, body); code != want {
		a.t.Errorf("%s %s %s: got %d, want %d (%v)", who, method, path, code, want, out)
	}
}

func TestScenarios(t *testing.T) {
	a := start(t)
	c := a.cast
	acme := func(name string) string { return a.signIn(name, c.Acme) }

	// 1. Reports need an application-wide role.
	a.expect("sue (support)", "GET", "/api/reports/usage", a.signIn("sue", ""), nil, 200)
	a.expect("sam (super admin)", "GET", "/api/reports/usage", a.signIn("sam", ""), nil, 200)
	a.expect("alice (Acme owner)", "GET", "/api/reports/usage", acme("alice"), nil, 403)

	// 2. Invoices in the organization the token is signed in to.
	hank, carol, bob := acme("hank"), acme("carol"), acme("bob")
	a.expect("hank (billing)", "POST", "/api/invoices", hank, map[string]any{"customer": "Wayne", "amount_cents": 1000}, 201)
	a.expect("carol (accountant)", "POST", "/api/invoices", carol, map[string]any{"customer": "Wayne", "amount_cents": 1000}, 403)
	a.expect("carol (accountant)", "GET", "/api/invoices", carol, nil, 200)
	a.expect("erin (no org role)", "GET", "/api/invoices", acme("erin"), nil, 403)

	// 3. Approving: the invoice's organization, and never your own.
	a.expect("hank (billing)", "POST", "/api/invoices/"+c.HanksInvoice+"/approve", hank, nil, 403)
	a.expect("bob (admin, own invoice)", "POST", "/api/invoices/"+c.BobsInvoice+"/approve", bob, nil, 403)
	a.expect("carol (accountant)", "POST", "/api/invoices/"+c.BobsInvoice+"/approve", carol, nil, 200)
	a.expect("carol (accountant)", "POST", "/api/invoices/"+c.GlobexInvoice+"/approve", carol, nil, 403)
	a.expect("carol (accountant)", "POST", "/api/invoices/missing/approve", carol, nil, 404)

	// 4. The organization in the path.
	a.expect("carol", "GET", "/api/orgs/"+c.Acme+"/billing", carol, nil, 200)
	a.expect("carol", "GET", "/api/orgs/"+c.Globex+"/billing", carol, nil, 403)
	a.expect("sue (support)", "GET", "/api/orgs/"+c.Globex+"/billing", a.signIn("sue", ""), nil, 200)

	// 5. The team in the path; roles flow down the tree.
	dave, erin, frank := acme("dave"), acme("erin"), acme("frank")
	backend, mobile, design := c.Teams["Backend"], c.Teams["Mobile"], c.Teams["Design"]
	a.expect("dave (lead of Engineering)", "POST", "/api/teams/"+mobile+"/projects", dave, map[string]string{"name": "Android app"}, 201)
	a.expect("dave (lead of Engineering)", "POST", "/api/teams/"+design+"/projects", dave, map[string]string{"name": "Logo"}, 403)
	a.expect("erin (developer on Backend)", "GET", "/api/teams/"+backend+"/projects", erin, nil, 200)
	a.expect("erin (developer on Backend)", "POST", "/api/teams/"+backend+"/projects", erin, map[string]string{"name": "Ledger"}, 403)
	a.expect("erin (developer on Backend)", "GET", "/api/teams/"+mobile+"/projects", erin, nil, 403)

	// 6. The team that owns the project.
	a.expect("erin", "PATCH", "/api/projects/"+c.PaymentsAPI, erin, map[string]string{"name": "Payments API v2"}, 200)
	a.expect("erin", "PATCH", "/api/projects/"+c.IOSApp, erin, map[string]string{"name": "x"}, 403)
	a.expect("frank (plain member)", "GET", "/api/projects/"+c.IOSApp, frank, nil, 403)
	a.expect("bob (admin)", "GET", "/api/projects/"+c.GlobexPortal, bob, nil, 403)

	// 7. A list across teams.
	_, body := a.call("GET", "/api/projects", erin, nil)
	if projects := body["projects"].([]any); len(projects) != 1 || body["all_teams"] != false {
		t.Errorf("erin sees %v", body)
	}
	_, body = a.call("GET", "/api/projects", dave, nil)
	if projects := body["projects"].([]any); len(projects) != 3 {
		t.Errorf("dave sees %d projects, want Payments API, iOS app and Android app: %v", len(projects), body)
	}
	_, body = a.call("GET", "/api/projects", acme("alice"), nil)
	if body["all_teams"] != true {
		t.Errorf("alice should see every team: %v", body)
	}

	// 8. A check in code.
	a.expect("erin (developer cannot archive)", "POST", "/api/projects/"+c.PaymentsAPI+"/archive", erin, nil, 403)
	a.expect("dave (lead)", "POST", "/api/projects/"+c.PaymentsAPI+"/archive", dave, nil, 200)

	// 9. AllowIf: the assignee completes the task without task:update.
	a.expect("frank (assignee)", "POST", "/api/tasks/"+c.FranksTask+"/complete", frank, nil, 200)
	a.expect("erin (not in Mobile)", "POST", "/api/tasks/"+c.FranksTask+"/complete", erin, nil, 403)

	// Not signed in.
	a.expect("anonymous", "GET", "/api/invoices", "", nil, 401)
}
