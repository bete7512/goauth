package fiberadapter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/gofiber/fiber/v2"
)

type routes []config.RouteInfo

func (r routes) Routes() []config.RouteInfo { return r }

// A handler that writes no body, such as a redirect or one that only sets
// cookies, must still reach the client with its status and every header.
func TestBodilessResponsesKeepStatusAndHeaders(t *testing.T) {
	app := fiber.New()
	Register(app, routes{
		{Name: "redirect", Method: http.MethodPost, Path: "/login", Handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "a"})
			http.SetCookie(w, &http.Cookie{Name: "refresh", Value: "r"})
			http.Redirect(w, r, "/home", http.StatusSeeOther)
		}},
		{Name: "empty", Method: http.MethodGet, Path: "/empty", Handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Test", "yes")
			w.WriteHeader(http.StatusNoContent)
		}},
		{Name: "nothing", Method: http.MethodGet, Path: "/nothing", Handler: func(http.ResponseWriter, *http.Request) {}},
		{Name: "body", Method: http.MethodGet, Path: "/body", Handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("a"))
			_, _ = w.Write([]byte("b"))
		}},
	})

	res, err := app.Test(httptest.NewRequest(http.MethodPost, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/home" {
		t.Fatalf("redirect: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if cookies := res.Cookies(); len(cookies) != 2 {
		t.Fatalf("want both cookies, got %v", res.Header.Values("Set-Cookie"))
	}

	res, err = app.Test(httptest.NewRequest(http.MethodGet, "/empty", nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusNoContent || res.Header.Get("X-Test") != "yes" {
		t.Fatalf("empty: %d %q", res.StatusCode, res.Header.Get("X-Test"))
	}

	res, err = app.Test(httptest.NewRequest(http.MethodGet, "/nothing", nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("nothing written: %d", res.StatusCode)
	}

	res, err = app.Test(httptest.NewRequest(http.MethodGet, "/body", nil))
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 8)
	n, _ := res.Body.Read(body)
	if res.StatusCode != http.StatusCreated || string(body[:n]) != "ab" {
		t.Fatalf("body: %d %q; the first WriteHeader wins, as in net/http", res.StatusCode, body[:n])
	}
}
