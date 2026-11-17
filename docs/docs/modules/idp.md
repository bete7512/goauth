---
id: idp
title: Identity Provider Module
seoTitle: "OpenID Connect provider in Go (OIDC server)"
description: "Make your Go app an OpenID Connect provider with GoAuth: other apps sign in with your accounts, with a built-in sign-in and consent page, ID tokens and discovery."
keywords: ["golang openid connect provider", "go oidc server", "oidc identity provider go", "sign in with your app", "golang oauth2 server"]
sidebar_label: Identity Provider
sidebar_position: 16
---

# Identity Provider Module

The identity provider (IdP) module makes your Go application an **OpenID Connect provider** (an OIDC server): other applications sign users in with your accounts ("Sign in with your application"). Each of them is registered as a **client** with a client ID and, unless it is a browser or mobile application, a client secret. After a sign-in the client receives an **ID token**, a signed statement of who the user is, and can read the user's profile from the UserInfo endpoint.

Any software that supports OpenID Connect can be a client: Grafana, GitLab, Nextcloud, internal tools, or another GoAuth application.

Users always sign in with your application, never with the client, so your policies (lockout, two-factor, email verification) apply and the client never sees a password. The module serves the page where that happens, a sign-in form followed by an approval screen, so nothing else has to be built. A host that wants the page in its own frontend can [bring its own](#your-own-page).

Status: **Experimental**. The authorization code flow with PKCE, refresh tokens, the sign-in and consent page, discovery, UserInfo and client administration are implemented. Sign-out protocols and silent sign-in (`prompt=none`) are not; see [Limitations](#limitations).

## Registration

```go
key, err := os.ReadFile("idp-signing-key.pem")
if err != nil {
    return err
}
if err := a.Use(idp.New(&config.IDPModuleConfig{
    SigningKey: config.IDPSigningKey{PrivateKeyPEM: key},
    AppName:    "Acme", // what the sign-in page calls your product
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

Initialization fails with a descriptive error when the signing key is missing or is not an RSA key, when it is the key that signs GoAuth's own access tokens, when the sign-in page cannot work (see [The sign-in page](#the-sign-in-page)), or when a declared client is invalid.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `SigningKey` | RSA private key that signs ID tokens (`PrivateKeyPEM` or `PrivateKeyFile`, optional `KeyID`). Required, at least 2048 bits, and a key of its own |
| `SigningKey.RetiredKeys` | Public keys of earlier signing keys, published until their `NotAfter` so that ID tokens they signed still verify |
| `Issuer` | Issuer identifier; default `{APIURL}{BasePath}/oidc`. Set it to the address clients reach when that differs, and route it to `{BasePath}/oidc` |
| `ConsentURL` | A page of your own frontend where the user signs in and approves. Empty (the default) uses the module's page at `{Issuer}/consent`. With `Security.AuthMode: "bearer"`, which the module's page cannot work with, the default is `{FrontendConfig.URL}/oidc/consent` |
| `AppName` | What your product is called on the module's page; default the issuer's host name |
| `ErrorURL` | Page shown when a request cannot be returned to the client; empty shows the module's page, or answers JSON when `ConsentURL` is set |
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
| `Name` | Shown to the user on the sign-in page |
| `RedirectURIs` | Exact addresses the user may be sent back to: https, http on a loopback host, or a private-use scheme of a native application |
| `Scopes` | What the client may request; must include `openid`. Default `openid`, `profile`, `email` |
| `Public` | An application that cannot keep a secret (single-page or mobile). It gets no secret and must use PKCE |
| `AllowWithoutPKCE` | Accept requests without a PKCE challenge, for older applications that cannot send one (`require_pkce: false` in the admin API). Ignored for a public client |
| `SkipConsent` | An application you operate yourself: users are signed in without being asked |
| `LogoURI`, `ClientURI` | Returned by the consent endpoints for a page of your own. The module's page shows the first letter of `Name` instead: loading a logo would tell another server who is about to sign in |
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
| GET | `/oidc/consent` | Browser | The sign-in and consent page (`?request_id=`) |
| POST | `/oidc/consent/signin` | Browser | The page's password form |
| POST | `/oidc/consent/2fa` | Browser | The page's two-factor form |
| POST | `/oidc/consent/decision` | Browser | The page's approve and cancel buttons |
| GET | `/oidc/assets/page.css` | Browser | The page's stylesheet |
| GET | `/oidc/consent/{id}` | Signed-in user | Describe a pending request |
| POST | `/oidc/consent/{id}/approve` | Signed-in user | Approve; returns the redirect to the client |
| POST | `/oidc/consent/{id}/deny` | Signed-in user | Refuse; returns the redirect to the client |
| GET | `/oidc/grants` | Signed-in user | List connected applications |
| DELETE | `/oidc/grants/{id}` | Signed-in user | Disconnect an application |
| GET, POST | `/admin/oidc/clients` | Administrator | List and register clients |
| GET, PUT, DELETE | `/admin/oidc/clients/{id}` | Administrator | Read, replace and delete a client |
| POST | `/admin/oidc/clients/{id}/secret` | Administrator | Rotate the client secret |

The first five speak the OpenID Connect wire format: errors are `{"error", "error_description"}`. The page routes answer HTML and are only registered when `ConsentURL` is empty. The others use the GoAuth response envelope.

## Flow

1. The client sends the browser to `/oidc/authorize` with its `client_id`, `redirect_uri`, `scope`, `state`, `nonce` and a PKCE challenge.
2. The module verifies the client, the exact redirect URI, the scopes and PKCE, stores the request for ten minutes and redirects the browser to the sign-in page: `/oidc/consent?request_id=...`.
3. The page looks at the application's credential cookies. A user who is not signed in gets a sign-in form; one who is goes straight on.
4. The page names the application, the account and what the application will learn, and asks. It does not ask for an application the user already approved with these scopes, or for one with `SkipConsent`: the browser goes straight back.
5. On **Continue** the module records the grant and redirects to the client's redirect URI with a one-time `code`, the `state` and the issuer (`iss`). On **Cancel** it redirects there with `error=access_denied`.
6. The client's server redeems the code at `/oidc/token` with its credentials and the PKCE verifier, and receives an `id_token`, an `access_token` and, with `offline_access`, a `refresh_token`.
7. The client verifies the ID token against `/oidc/jwks` and may read `/oidc/userinfo` with the access token.

### The sign-in page

The page is plain HTML: forms and one stylesheet, no script, light and dark. It needs nothing but this module.

- **Who is signed in** is whoever your application's credential cookies say, so a user who is signed in to your application is signed in here, and signing in here signs the browser in to your application. An expired access token is renewed from the refresh cookie.
- **Signing in** goes through the same code as your login route: password with email or username, then a two-factor code when the Two-Factor module asks for one. Lockout, bans and email verification apply. Connections of the OAuth and SAML modules appear as buttons and come back to the page with cookies only.
- **Use another account** on the approval screen shows the sign-in form without signing anyone out.
- Passkeys and emailed sign-in codes are not offered on this page, and there is no sign-up or password-reset form: users who need those use your application first.

Requirements, checked at `Initialize`:

- Cookies: `Security.AuthMode` must be `"cookie"` or `"both"` (the default allows them). A browser that only holds a bearer token, such as a single-page application that keeps tokens in memory, is asked to sign in on the page once.
- `Security.Session.Path` must cover the page (`"/"`, the default, does).
- With `Security.Session.SameSite` set to `Strict`, cookies do not travel with the navigation that brings the user from the client, so the page reloads itself once to pick them up. `Lax`, the default, needs no extra step.

### Your own page

Set `ConsentURL` to a page of your frontend and the module's page is not served. The browser arrives there with `?request_id=...`, and the page uses the JSON endpoints:

1. Make sure the user is signed in, the usual way, and call `GET /oidc/consent/{request_id}`. The answer names the application, lists the scopes and says whether there is anything to ask (`consent_required`) and whether the application wants a fresh sign-in (`login_required`).
2. Show the prompt, or skip it, and call `POST /oidc/consent/{request_id}/approve` or `/deny`. The answer's `redirect_to` is where to send the browser.

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

- `prompt=login` and `max_age` ask for a recent sign-in. When the user's current one is too old, the page asks for the password again; for a page of your own, `login_required` is true and approving fails with `IDP_LOGIN_REQUIRED` until the user signs in again. The request stays open meanwhile, and a sign-in made after the request satisfies it however long the user then takes to approve.
- `prompt=consent` asks for approval even when it was given before. It has no effect on a `SkipConsent` client.
- `login_hint` fills in the sign-in form, and is passed on to a page of your own.
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
- **CSRF.** The token and UserInfo endpoints are called by servers and carry their own credentials, so the CSRF module leaves them alone. The forms of the module's page are wrapped in `net/http`'s `CrossOriginProtection`, which refuses a form another site submits, and need no token of the CSRF module. A decision made from a page of your own goes through the JSON endpoints and is protected like any other request of the signed-in user.
- **The page cannot be framed or scripted.** Its Content Security Policy allows no script at all, no inline style and nothing from another origin, and `frame-ancestors 'none'` keeps another site from putting the approve button under a click. Forms may only post to the page itself and, after the decision, redirect to the client the request came from.
- **The answer belongs to the account that was asked.** Approving counts only for the user the approval screen was shown to; a browser that changed accounts in between is asked again.
- **Rate limits.** By default the authorization endpoint is limited to 60 requests a minute per IP, the token and UserInfo endpoints to 300, and the page's password and two-factor forms like every other credential check (30 a minute per IP, 10 per account in ten minutes).

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

`examples/idp` is a runnable host. Its `interop/interop.sh` signs a user in to a real client in a container, through the module's page, and checks the result; it passes with Grafana 11.4 and with oauth2-proxy 7.6, which reads the discovery document and verifies the ID token signature.

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
- No silent sign-in: `prompt=none` is answered with `interaction_required`.
- The module's page signs in with a password, a two-factor code, OAuth and SAML. It has no passkey or emailed-code sign-in, no sign-up and no password reset, and it does not show client logos.
- Authorization code flow only. The implicit and hybrid flows, request objects, the `claims` parameter, pairwise subjects and encrypted ID tokens are not supported.
- ID tokens are signed with RS256 only.
- Clients authenticate with a secret or, when public, with PKCE. There is no `private_key_jwt` and no dynamic client registration.
- Access tokens are for the UserInfo endpoint only; they are not JWTs and carry no audience for your APIs.
- Clients are global, not per organization.
- The module has not been run against the OpenID Foundation conformance suite.
