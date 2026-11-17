---
slug: openid-connect-provider-go
title: Build an OpenID Connect Provider in Go
description: Build an OpenID Connect provider in Go with GoAuth's idp module, so Grafana and other apps can offer "Sign in with" your accounts using code flow and PKCE.
keywords: ["openid connect provider go", "golang oidc provider", "go oidc server", "build oidc provider", "golang identity provider", "sign in with your app oidc"]
authors: [goauth-team]
tags: [oidc, sso, go, authentication, tutorial]
---

# Build an OpenID Connect Provider in Go

Once you have users, other applications may want to sign them in: an internal dashboard, Grafana, a partner tool. OpenID Connect is the standard way to do that. This guide turns a Go (Golang) server into an OpenID Connect provider with GoAuth's idp module, and signs a user in to Grafana with it.

<!-- truncate -->

## What you will build

A Go server that:

- Publishes an issuer at `http://localhost:8080/auth/oidc` with a discovery document and a JWKS.
- Runs the authorization code flow with PKCE, issues RS256 ID tokens and serves UserInfo.
- Sends users to a consent page of your own, where they sign in and approve the client.

The idp module is **experimental**. Sign-out protocols (RP-initiated and back-channel logout) and silent sign-in (`prompt=none`) are not implemented yet.

## Prerequisites

- Go 1.26 or later, and a C compiler for the SQLite driver.
- The program from the [Quick Start](/docs/quickstart).
- `openssl`, and Docker if you want to try Grafana.

## Step 1: Create a signing key

ID tokens are verified with a public key, so the module needs an RSA key of its own, at least 2048 bits. It must not be the key that signs GoAuth's own access tokens; `Initialize` refuses a shared key.

```sh
openssl genrsa -out idp-signing-key.pem 2048
export GRAFANA_OIDC_SECRET="$(openssl rand -hex 32)"
```

## Step 2: Register the module

The issuer is derived from `APIURL` and `BasePath`, so set `APIURL` in the root config. Clients compare the issuer character by character.

```go
import "github.com/bete7512/goauth/pkg/modules/idp"

a, err := auth.New(&config.Config{
    Storage:   store,
    APIURL:    "http://localhost:8080",
    BasePath:  "/auth", // issuer: http://localhost:8080/auth/oidc
    Migration: config.MigrationConfig{Auto: true},
    Core:      &config.CoreConfig{},
    Security: types.SecurityConfig{
        JwtSecretKey:  os.Getenv("JWT_SECRET_KEY"),
        EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
        Session:       types.SessionConfig{AllowInsecureCookies: true}, // localhost only
    },
})
// handle err, defer a.Close()

key, err := os.ReadFile("idp-signing-key.pem")
if err != nil {
    return err
}
if err := a.Use(idp.New(&config.IDPModuleConfig{
    SigningKey: config.IDPSigningKey{PrivateKeyPEM: key},
    ConsentURL: "http://localhost:8080/oidc/consent",
    Clients: []config.IDPClientConfig{{
        ClientID:     "grafana",
        Secret:       os.Getenv("GRAFANA_OIDC_SECRET"), // at least 32 characters
        Name:         "Grafana",
        RedirectURIs: []string{"http://localhost:3000/login/generic_oauth"},
        Scopes:       []string{"openid", "profile", "email"},
    }},
})); err != nil {
    return err
}
```

Clients in `Clients` are created or rewritten at every start, and only the secret's digest is stored. Redirect URIs must match exactly; plain `http` is allowed only on a loopback host. For a client you operate yourself, `SkipConsent: true` signs users in without asking. Add `offline_access` to `Scopes` if the client should get refresh tokens.

To register clients at runtime instead, set `AdminAPI: true`. That serves `/admin/oidc/clients` and requires the Admin module.

## Step 3: Serve the consent page

GoAuth has no login page of its own. `/oidc/authorize` checks the request, stores it, and redirects the browser to `ConsentURL?request_id=...`. Your page signs the user in the usual way, then reports the decision.

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /oidc/consent", func(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "consent.html")
})
return http.ListenAndServe(":8080", stdhttp.Register(mux, a))
```

The script on that page, once it has the user's access token from `POST /auth/login`:

```js
const id = new URLSearchParams(location.search).get("request_id");
const call = (path, method = "GET") =>
  fetch(`/auth/oidc/consent/${encodeURIComponent(id)}${path}`, {
    method,
    headers: { Authorization: `Bearer ${accessToken}` },
  }).then((r) => r.json());

async function decide() {
  const { data } = await call("");
  if (data.login_required) {
    // prompt=login or max_age: the current sign-in is too old.
    return signInAgain();
  }
  const approved = !data.consent_required || (await askUser(data.client.name, data.scopes));
  const decision = await call(approved ? "/approve" : "/deny", "POST");
  location.replace(decision.data.redirect_to);
}
```

`consent_required` is false when the user already approved these scopes or the client has `SkipConsent`. `redirect_to` is the client's redirect URI with a one-time `code`, the `state` and `iss`. Serve this page with a strict Content-Security-Policy and `frame-ancestors 'none'`: it decides who signs in where.

`examples/idp` in the repository is a complete version of this server and page. Run it from the `examples` directory with `go run ./idp`.

## Step 4: Connect Grafana

Check the discovery document first:

```bash
curl http://localhost:8080/auth/oidc/.well-known/openid-configuration
```

Then start Grafana with the generic OAuth provider pointed at the issuer:

```sh
docker run --rm --network host \
  -e GF_AUTH_GENERIC_OAUTH_ENABLED=true \
  -e GF_AUTH_GENERIC_OAUTH_NAME=GoAuth \
  -e GF_AUTH_GENERIC_OAUTH_CLIENT_ID=grafana \
  -e GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$GRAFANA_OIDC_SECRET" \
  -e GF_AUTH_GENERIC_OAUTH_SCOPES="openid profile email" \
  -e GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://localhost:8080/auth/oidc/authorize \
  -e GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://localhost:8080/auth/oidc/token \
  -e GF_AUTH_GENERIC_OAUTH_API_URL=http://localhost:8080/auth/oidc/userinfo \
  -e GF_AUTH_GENERIC_OAUTH_USE_PKCE=true \
  grafana/grafana:11.4.0
```

Open `http://localhost:3000` and choose **Sign in with GoAuth**. Host networking works on Linux.

## How the flow works

1. The client sends the browser to `/auth/oidc/authorize` with `client_id`, `redirect_uri`, `scope`, `state`, `nonce` and a PKCE challenge.
2. GoAuth verifies the client, the exact redirect URI, the scopes and PKCE, stores the request for ten minutes, and redirects to your consent page.
3. Your page signs the user in, reads `GET /auth/oidc/consent/{id}`, and posts `approve` or `deny`.
4. The client's server redeems the code at `/auth/oidc/token` with its secret and the PKCE verifier. It receives an `id_token`, an `access_token` and, with `offline_access`, a `refresh_token`.
5. The client verifies the ID token against `/auth/oidc/jwks` and may call `/auth/oidc/userinfo`.

Every login method you already have (passwords, passkeys, two-factor, lockout) applies, because the user signs in on your pages. The client never sees a password.

## Security notes

- **A separate signing key.** An ID token given to another app can never be used as an access token for your API.
- **Opaque access tokens.** The access token only works at UserInfo. It is not a credential for your own API.
- **PKCE by default**, `S256` only. `AllowWithoutPKCE` exists for older confidential clients; avoid it when the client supports PKCE.
- **Digests at rest.** Secrets, codes, access and refresh tokens are stored as digests.
- **Leak detection.** A code redeemed twice, or a rotated refresh token reused after the leeway, disconnects the client for that user and emits an event.
- **Logout is separate.** Signing out of your app does not disconnect clients. Changing the password ends their tokens; `DELETE /auth/oidc/grants/{id}` ends them and removes the consent.
- **Rate limits** on the authorize and token endpoints are on by default.

## Next steps

- [Identity Provider module reference](/docs/modules/idp), with every config field and limitation
- [Admin module](/docs/modules/admin), for runtime client registration
- [Security guide](/docs/security)
- [Production checklist](/docs/production)
