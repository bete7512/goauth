package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/pkg/types"
)

// jwksProvider is the subset of the SecurityManager exposing the public key set.
// Only concrete implementations that serve an asymmetric algorithm populate it.
type jwksProvider interface {
	JWKS() types.JWKS
	JWTAlgorithm() types.JWTAlgorithm
}

// JWKS serves the public JSON Web Key Set used by downstream verifiers
// (API gateways, microservices) to validate access and stateless refresh tokens.
// Returns 404 when the configured algorithm is HS256 — the symmetric secret
// must not be exposed over HTTP.
func (h *CoreHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	provider, ok := h.deps.SecurityManager.(jwksProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !provider.JWTAlgorithm().IsAsymmetric() {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(provider.JWKS())
}
