package config

import "net/http"

type PasswordPolicy struct {
	HashSaltLength int
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

type CookieConfig struct {
	Name     string
	Secure   bool
	HttpOnly bool
	Domain   string
	Path     string
	MaxAge   int
	SameSite http.SameSite
}
