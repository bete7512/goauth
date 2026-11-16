// Command rbac is a runnable example of GoAuth's role-based access control
// in an application shaped like a real one: "Acme Tracker", where
// organizations have nested teams, teams own projects and tasks, and
// organizations own invoices.
//
// Run it from the examples directory:
//
//	go run ./rbac
//
// then follow README.md, or run ./rbac/walkthrough.sh in another terminal.
// The admin console is at http://localhost:8080/admin (sign in as
// sam@tracker.test). Everything is kept in memory.
//
// Layout:
//
//	main.go                    wiring and the HTTP server
//	internal/platform          GoAuth: modules, roles, settings
//	internal/tracker           the application's own domain and store
//	internal/api               the JSON API; router.go holds every guard
//	internal/seed              demo users, organizations, teams and data
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bete7512/goauth/examples/rbac/internal/api"
	"github.com/bete7512/goauth/examples/rbac/internal/platform"
	"github.com/bete7512/goauth/examples/rbac/internal/seed"
	"github.com/bete7512/goauth/examples/rbac/internal/tracker"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	port := envOr("PORT", "8080")
	p, err := platform.New(ctx, platform.Settings{
		Origin: "http://localhost:" + port,
		// Demo values. Load real secrets from the environment.
		JWTSecret:     envOr("JWT_SECRET", "rbac-example-jwt-secret-change-me-32"),
		EncryptionKey: envOr("ENCRYPTION_KEY", "rbac-example-encryption-key-32chr"),
		DSN:           os.Getenv("DATABASE_DSN"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer p.Close()

	mux := http.NewServeMux()
	handler := p.Mount(mux)

	store := tracker.NewStore()
	api.New(store, p.Authz, p.TeamOrg).Routes(mux, p.Auth.RequireAuth)

	cast, err := seed.Run(ctx, p, handler, store)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}
	cast.Print(os.Stdout)
	// Demo only: the seeded IDs, for walkthrough.sh. A real application has
	// nothing like this.
	mux.HandleFunc("GET /demo/cast", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cast)
	})

	server := &http.Server{Addr: ":" + port, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Acme Tracker on http://localhost:%s (admin console: /admin)", port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
