package main

import (
	"context"
	"log"
	"net/http"

	"github.com/bete7512/goauth/modules/magiclink"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
)

func main() {
	// Application code here
	auth, err := auth.New(
		&config.Config{
			// Configuration fields here
		},
	)
	if err != nil {
		// Handle error
	}

	if err := auth.Initialize(context.Background()); err != nil {
		// Handle error
	}
	auth.Use(magiclink.New())
	mux := http.NewServeMux()
	for _, route := range auth.Routes() {
		log.Println("Registering route:", route.Method, route.Path)
		mux.Handle(route.Path, route.Handler)
		mux.Handle(route.Path, auth.RequireAuth(route.Handler))
	}

	http.ListenAndServe(":8080", mux)
}
