package main

import (
	"log"
	"time"

	"github.com/bete7512/go-auth/auth"
	"github.com/bete7512/go-auth/auth/config"
	"github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

func main() {
	authHandler, err := config.NewBuilder().
		WithServer(types.GinServer).
		WithDatabase(types.PostgreSQL, "postgres://postgres:password@localhost:5432/auth_db").
		WithJWT("your-secret-key", 15*time.Minute, 7*24*time.Hour).
		WithProvider(types.Google, types.ProviderConfig{
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Scopes:       []string{"email", "profile"},
		}).
		WithPasswordPolicy(types.PasswordPolicy{
			MinLength:      3,
			RequireUpper:   true,
			RequireLower:   true,
			RequireNumber:  true,
			RequireSpecial: true,
		}).
		WithCookie(true, "test.ideablock.com").
		Build()
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()

	ginAuthService, err := auth.NewAuth(authHandler.Config)
	if err != nil {
		log.Fatal(err)
	}
	ginAuthService.GinAuthRoutes(r)
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
