---
id: idp
title: Identity Provider Module
sidebar_label: Identity Provider
sidebar_position: 16
---

# Identity Provider Module

The identity provider (IdP) module makes your application an **OpenID Connect provider**: other applications sign users in with your accounts ("Sign in with your application"). Each of them is registered as a **client** with a client ID and, unless it is a browser or mobile application, a client secret. After a sign-in the client receives an **ID token**, a signed statement of who the user is, and can read the user's profile from the UserInfo endpoint.

Any software that supports OpenID Connect can be a client: Grafana, GitLab, Nextcloud, internal tools, or another GoAuth application.

Users always sign in on your own pages, so every login method and policy you have (passwords, passkeys, two-factor, lockout) applies, and the client never sees a password.

Status: **Experimental**. The authorization code flow with PKCE, refresh tokens, consent, discovery, UserInfo and client administration are implemented. Sign-out protocols and silent sign-in (`prompt=none`) are not; see [Limitations](#limitations).

## Registration

```go
key, err := os.ReadFile("idp-signing-key.pem")
if err != nil {
    return err
}
if err := a.Use(idp.New(&config.IDPModuleConfig{
    SigningKey: config.IDPSigningKey{PrivateKeyPEM: key},
    ConsentURL: "https://app.example.com/oidc/consent",
    Clients: []config.IDPClientConfig{{
        ClientID:     "grafana",
        Secret:       os.Getenv("GRAFANA_OIDC_SECRET"), // at least 32 characters
        Name:         "Grafana",
        RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"},
        SkipConsent:  true, // an application you operate yourself
    }},
})); err != nil {
    return err
}
```

Import `pkg/modules/idp`, `pkg/config` and `os`. Set `config.Config.APIURL`, for example `https://api.example.com`; with `BasePath: "/auth"` the issuer is `https://api.example.com/auth/oidc` and a client is configured with that one address. Everything else it needs is in the discovery document at `{issuer}/.well-known/openid-configuration`.

Generate the signing key and a client secret with:

```sh
openssl genrsa -out idp-signing-key.pem 2048
openssl rand -hex 32
```

The module depends on Core only. With `AdminAPI: true` it also **depends on the Admin module**, whose middleware protects the client administration endpoints.

Initialization fails with a descriptive error when the signing key is missing or is not an RSA key, when it is the key that signs GoAuth's own access tokens, when no consent page is known, or when a declared client is invalid.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `SigningKey` | RSA private key that signs ID tokens (`PrivateKeyPEM` or `PrivateKeyFile`, optional `KeyID`). Required, at least 2048 bits, and a key of its own |
| `SigningKey.RetiredKeys` | Public keys of earlier signing keys, published until their `NotAfter` so that ID tokens they signed still verify |
| `Issuer` | Issuer identifier; default `{APIURL}{BasePath}/oidc`. Set it to the address clients reach when that differs, and route it to `{BasePath}/oidc` |
| `ConsentURL` | Page of your frontend where the user signs in and approves; default `{FrontendConfig.URL}/oidc/consent` |
| `ErrorURL` | Page shown when a request cannot be returned to the client; empty answers JSON |
| `Clients` | Clients created or rewritten from configuration at every start |
| `AdminAPI` | Serve `/admin/oidc/clients` for registering clients at runtime (default off; needs the Admin module) |
| `IDTokenTTL` | ID token lifetime, default 1 hour |
| `AccessTokenTTL` | Lifetime of the access token for UserInfo, default 1 hour |
| `RefreshTokenTTL` | How long an unused refresh token stays valid, default 30 days; each rotation starts a new period |
| `RefreshTokenReuseLeeway` | How long a rotated refresh token is answered with a plain error instead of being treated as stolen, default 10 seconds; negative disables it |
| `AuthorizationCodeTTL` | Authorization code lifetime, default 60 seconds, at most 10 minutes |
| `AuthorizationRequestTTL` | How long a request waits for the user's decision, default 10 minutes |
| `CleanupInterval` | How often expired requests, codes and tokens are deleted, default 1 hour; negative disables it. The token store is shared, so expired records of other modules (verification links, password resets) are removed too |
| `Claims` | Function that adds your own claims, such as roles or groups, to ID tokens and UserInfo |

Per client (`IDPClientConfig`, and the same fields in the admin API):

| Field | Effective behavior |
| --- | --- |
| `ClientID` | Public identifier: 3 to 128 characters of letters, digits, `.`, `_`, `~` or `-` |
| `Secret` | Client secret, at least 32 characters. Only its digest is stored. Empty for a `Public` client |
| `Name` | Shown to the user on the consent page |
| `RedirectURIs` | Exact addresses the user may be sent back to: https, http on a loopback host, or a private-use scheme of a native application |
| `Scopes` | What the client may request; must include `openid`. Default `openid`, `profile`, `email` |
| `Public` | An application that cannot keep a secret (single-page or mobile). It gets no secret and must use PKCE |
| `AllowWithoutPKCE` | Accept requests without a PKCE challenge, for older applications that cannot send one (`require_pkce: false` in the admin API). Ignored for a public client |
| `SkipConsent` | An application you operate yourself: users are signed in without being asked |
| `LogoURI`, `ClientURI` | Shown on the consent page |
| `Disabled` | Keep the client registered but refuse it |

A client declared in configuration is read-only through the admin API. When it is removed from configuration it is disabled and handed over to the admin API, where it can be deleted.

### Scopes and claims

| Scope | Claims released |
| --- | --- |
| `openid` | `sub` (the user's ID). Required |
| `profile` | `name`, `given_name`, `family_name`, `preferred_username`, `picture`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `offline_access` | No claims; the token response includes a refresh token |

The claims appear in both the ID token and the UserInfo response, because many applications read only one of the two. Empty values are left out. Every ID token also carries `iss`, `aud`, `exp`, `iat`, `at_hash`, and, when known, `auth_time`, `amr` and `nonce`.

Scopes a client asks for but is not registered for are left out rather than refused; the token response's `scope` states what was granted.

A `Claims` function adds claims of your own:

```go
Claims: func(ctx context.Context, r config.IDPClaimsRequest) (map[string]interface{}, error) {
    groups, err := groupsOf(ctx, r.User.ID)
    return map[string]interface{}{"groups": groups}, err
},
```

It cannot replace the claims the module sets (`sub`, `iss`, `aud` and the like), it receives a copy of the user, and an error fails the token request. An ID token's claims are limited to 4 KB.

## Endpoints

All paths are relative to `BasePath`.

| Method | Path | Called by | Description |
| --- | --- | --- | --- |
| GET | `/oidc/.well-known/openid-configuration` | Client | Discovery document |
| GET | `/oidc/jwks` | Client | Public keys that verify ID tokens |
| GET | `/oidc/authorize` | Browser | Start a sign-in |
| POST | `/oidc/token` | Client | Redeem a code or a refresh token |
| GET, POST | `/oidc/userinfo` | Client | Claims about the user |
| GET | `/oidc/consent/{id}` | Signed-in user | Describe a pending request |
| POST | `/oidc/consent/{id}/approve` | Signed-in user | Approve; returns the redirect to the client |
| POST | `/oidc/consent/{id}/deny` | Signed-in user | Refuse; returns the redirect to the client |
| GET | `/oidc/grants` | Signed-in user | List connected applications |
| DELETE | `/oidc/grants/{id}` | Signed-in user | Disconnect an application |
| GET, POST | `/admin/oidc/clients` | Administrator | List and register clients |
| GET, PUT, DELETE | `/admin/oidc/clients/{id}` | Administrator | Read, replace and delete a client |
| POST | `/admin/oidc/clients/{id}/secret` | Administrator | Rotate the client secret |

The first five speak the OpenID Connect wire format: errors are `{"error", "error_description"}`. The others use the GoAuth response envelope.

## Flow

1. The client sends the browser to `/oidc/authorize` with its `client_id`, `redirect_uri`, `scope`, `state`, `nonce` and a PKCE challenge.
2. The module verifies the client, the exact redirect URI, the scopes and PKCE, stores the request for ten minutes and redirects the browser to `ConsentURL?request_id=...`.
3. Your consent page makes sure the user is signed in, the usual way, and calls `GET /oidc/consent/{request_id}`. The answer names the application, lists the scopes and says whether there is anything to ask: `consent_required` is false for an application the user already approved with these scopes, and for one with `SkipConsent`.
4. The page shows the prompt, or skips it, and calls `POST /oidc/consent/{request_id}/approve`. The module records the grant and answers with `redirect_to`: the client's redirect URI carrying a one-time `code`, the `state` and the issuer (`iss`). The page sends the browser there.
5. The client's server redeems the code at `/oidc/token` with its credentials and the PKCE verifier, and receives an `id_token`, an `access_token` and, with `offline_access`, a `refresh_token`.
6. The client verifies the ID token against `/oidc/jwks` and may read `/oidc/userinfo` with the access token.

A minimal consent page:

```js
const id = new URLSearchParams(location.search).get("request_id");
const api = (path, method = "GET") =>
  fetch(`/auth/oidc/consent/${id}${path}`, { method, headers: { Authorization: `Bearer ${accessToken}` } })
    .then((r) => r.json());

const { data } = await api("");
if (data.login_required) return signInAgain();          // prompt=login or max_age
if (!data.consent_required || (await askUser(data))) {
  location.href = (await api("/approve", "POST")).data.redirect_to;
} else {
  location.href = (await api("/deny", "POST")).data.redirect_to;
}
```

### What a client asks for

- `prompt=login` and `max_age` ask for a recent sign-in. When the user's current one is too old, `login_required` is true and approving fails with `IDP_LOGIN_REQUIRED` until the user signs in again. The request stays open meanwhile.
- `prompt=consent` asks for approval even when it was given before. It has no effect on a `SkipConsent` client.
- `login_hint` is passed on to the consent page.
- `prompt=none` is answered with `interaction_required`; see [Limitations](#limitations).

### Lifetime of a connection

A **grant** records that a user approved a client, with the scopes. There is one per user and client, and every token names it.

- Signing out of your application does **not** disconnect clients.
- Changing, setting or resetting the password ends the client's tokens. The consent stays, so the next sign-in needs no new approval.
- A user who is deactivated, or lacks an email or phone verification you require, gets nothing from tokens issued earlier.
- Refreshing runs your authentication policy the way a session refresh does: a user who may no longer refresh a session of their own gets no new tokens for a client either.
- The user disconnects a client with `DELETE /oidc/grants/{id}`; your code disconnects all of a user's clients with `idp.RevokeUserGrants(ctx, module, userID)`. Both end the tokens at once and remove the consent.
- A refresh token rotates on every use. A rotated one that shows up again after the reuse leeway was copied: the client is disconnected and `EventIDPTokenReuseDetected` is emitted.
- An authorization code is redeemed once. A second redemption fails and disconnects the client for that user, because a code seen twice has leaked.
- When an administrator deletes a user, the user's grants are removed with the account.

## Security Model

- **A key of its own.** ID tokens are signed with the module's RSA key, never with the key that signs GoAuth's access tokens, and initialization refuses a shared key. An ID token handed to another application is therefore never accepted as an access token here.
- **Opaque access tokens.** The access token is a random value that only the UserInfo endpoint understands. It is not a credential for your own API; issuing access tokens for APIs is a different job.
- **Nothing redeemable at rest.** Client secrets, pending requests, codes, access tokens and refresh tokens are stored as digests.
- **Exact redirect URIs.** A redirect URI must equal a registered one, except that a loopback address matches on any port. A request whose client or redirect URI cannot be verified is never redirected.
- **PKCE by default.** `S256` only. Required for every client unless a confidential one is explicitly allowed to go without, in which case the redirect URI must be repeated at the token endpoint.
- **CSRF.** The token and UserInfo endpoints are called by servers and carry their own credentials, so the CSRF module leaves them alone. The consent decision is made from your page and is protected like any other request of the signed-in user.
- **Rate limits.** By default the authorization endpoint is limited to 60 requests a minute per IP, and the token and UserInfo endpoints to 300.

## Client Quick Start: Grafana

```ini
[auth.generic_oauth]
enabled = true
name = Your Application
client_id = grafana
client_secret = <the Secret from IDPClientConfig>
scopes = openid profile email
auth_url = https://api.example.com/auth/oidc/authorize
token_url = https://api.example.com/auth/oidc/token
api_url = https://api.example.com/auth/oidc/userinfo
use_pkce = true
```

The redirect URI to register is `https://<grafana>/login/generic_oauth`.

`examples/idp` is a runnable host with a consent page. Its `interop/interop.sh` signs a user in to a real client in a container and checks the result; it passes with Grafana 11.4 and with oauth2-proxy 7.6, which reads the discovery document and verifies the ID token signature.

## Events and Errors

Events carry `IDPEventData` (user, actor, client, scopes, grant, reason):

| Event | When |
| --- | --- |
| `EventIDPConsentGranted` | A user signed in to a client |
| `EventIDPConsentDenied` | A user refused a request |
| `EventIDPTokenIssued` | The token endpoint issued tokens |
| `EventIDPTokenReuseDetected` | A rotated refresh token was presented again |
| `EventIDPGrantRevoked` | A client was disconnected, with the reason |
| `EventIDPClientCreated`, `EventIDPClientUpdated`, `EventIDPClientDeleted`, `EventIDPClientSecretRotated` | Client administration |

The Audit module records all of them except token issuance, which happens on every refresh.

Error codes of the consent, grant and admin endpoints: `IDP_REQUEST_NOT_FOUND`, `IDP_LOGIN_REQUIRED`, `IDP_GRANT_NOT_FOUND`, `IDP_CLIENT_NOT_FOUND`, `IDP_CLIENT_EXISTS`, `IDP_INVALID_CLIENT`, `IDP_CLIENT_MANAGED`.

The protocol endpoints answer with OAuth error codes: `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `unsupported_grant_type`, `unsupported_response_type`, `access_denied`, `interaction_required`, `request_not_supported`, `request_uri_not_supported`, `invalid_token`, `insufficient_scope`, `server_error`.

## Limitations

- No sign-out protocol: neither RP-initiated logout nor back-channel logout. A client's own session ends on its own terms.
- No silent sign-in: `prompt=none` is answered with `interaction_required`, because whether the user is signed in is known to your frontend, not to the authorization endpoint.
- Authorization code flow only. The implicit and hybrid flows, request objects, the `claims` parameter, pairwise subjects and encrypted ID tokens are not supported.
- ID tokens are signed with RS256 only.
- Clients authenticate with a secret or, when public, with PKCE. There is no `private_key_jwt` and no dynamic client registration.
- Access tokens are for the UserInfo endpoint only; they are not JWTs and carry no audience for your APIs.
- Clients are global, not per organization.
- The module has not been run against the OpenID Foundation conformance suite.
