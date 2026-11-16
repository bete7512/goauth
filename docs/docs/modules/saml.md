---
id: saml
title: SAML Module
sidebar_label: SAML
sidebar_position: 15
---

# SAML Module

SAML provides SAML 2.0 Web Browser SSO with GoAuth acting as the **service provider (SP)**. Each named connection points at one **identity provider (IdP)** such as a Keycloak realm, Okta, Microsoft Entra ID or Shibboleth. A verified assertion enters the same completion service as password, OAuth, passkey and magic-link authentication, so lockout, eligibility checks, two-factor challenges and session or stateless issuance behave identically.

The protocol work (XML canonicalization, XML signature verification, assertion decryption, audience, destination, validity window and `InResponseTo` checks) is delegated to [`crewjam/saml`](https://github.com/crewjam/saml). The module wraps it behind a small interface so handlers, services and tests never touch the library directly.

Status: **Experimental**. SP-initiated login, optional IdP-initiated login and SP metadata are implemented. Single Logout, the artifact binding and attribute queries are not.

## Registration

```go
if err := a.Use(oauth.New(nil)); err != nil { // owns the shared accounts table
    return err
}
if err := a.Use(saml.New(&config.SAMLModuleConfig{
    SPCertificate: os.Getenv("SAML_SP_CERT"), // PEM
    SPPrivateKey:  os.Getenv("SAML_SP_KEY"),  // PEM
    Providers: map[string]*config.SAMLProviderConfig{
        "keycloak": {
            MetadataURL:  "http://localhost:8180/realms/demo/protocol/saml/descriptor",
            NameIDFormat: "persistent",
            SignRequests: true,
        },
    },
    AllowSignup:        true,
    TrustEmail:         true,
    DefaultRedirectURL: "http://localhost:3000/auth/callback",
})); err != nil {
    return err
}
```

Import `pkg/modules/saml`, `pkg/modules/oauth`, `pkg/config` and `os`. Set `config.Config.APIURL`, for example `http://localhost:8080`; with `BasePath: "/api/v1"` the SP endpoints are `http://localhost:8080/api/v1/saml/keycloak/{login,acs,metadata}`.

The module **depends on the OAuth module**. Linked SAML subjects are stored in the `accounts` table that the OAuth module owns and migrates, so `oauth.New(nil)` must be registered too; it needs no providers.

IdP metadata is loaded once during `Initialize()`. An unreachable `MetadataURL`, a document without an `IDPSSODescriptor`, or an IdP without an HTTP-Redirect single sign-on endpoint fails initialization with a descriptive error.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `SPCertificate`, `SPPrivateKey` | PEM key pair advertised in SP metadata. Needed to sign requests and to receive encrypted assertions. Both or neither. |
| `Providers` | Named connections; the key appears in URLs and on linked accounts (`[a-z0-9][a-z0-9_-]{0,63}`) |
| `DefaultRedirectURL` | Frontend destination after login; empty returns the JSON auth response |
| `ErrorRedirectURL` | Error destination with `error` / `error_description` query parameters |
| `AllowSignup` | Create a user for an unknown subject (nil config: true) |
| `AllowAccountLinking` | Link an unknown subject to an existing user with the same email; requires `TrustEmail` (default false) |
| `TrustEmail` | Mark the IdP-released email as verified (nil config: true) |
| `RequestTTL` | How long an outstanding AuthnRequest waits for its response, default 10 minutes |
| `UseSessionAuth` | Create a database session instead of stateless tokens |
| `MetadataHTTPClient` | Client used to fetch `MetadataURL`, default 15 second timeout |

Per connection:

| Field | Effective behavior |
| --- | --- |
| `MetadataURL` / `MetadataXML` | IdP metadata, exactly one of the two |
| `EntityID` | SP entity ID override, default `{APIURL}{BasePath}/saml/{name}/metadata` |
| `NameIDFormat` | `persistent` (default), `emailAddress`, `unspecified`, `transient`, or a full URN |
| `SignRequests` | Sign AuthnRequests (RSA-SHA256 or ECDSA-SHA256). Keycloak's "Client signature required" default needs this |
| `AllowIDPInitiated` | Accept unsolicited responses that start at the IdP (default false) |
| `Attributes` | Attribute names for `Email`, `Name`, `FirstName`, `LastName`, `Username`, `Groups` |
| `Disabled` | Keep the connection configured but not served |

Attribute mapping tries the configured name first, then built-in fallbacks: plain names (`email`, `firstName`, `lastName`, `displayName`), LDAP OIDs (`urn:oid:1.2.840.113549.1.9.1`, `urn:oid:2.5.4.42`, `urn:oid:2.5.4.4`) and WS-Fed claim URIs used by Entra ID and ADFS. When no email attribute is released but the NameID format is `emailAddress`, the NameID is the email.

## Endpoints

All paths are relative to `BasePath`.

| Method | Path | Access auth | Description |
| --- | --- | --- | --- |
| GET | `/saml/providers` | No | List connections with login and metadata URLs |
| GET | `/saml/{provider}/login` | No | Build an AuthnRequest and redirect to the IdP (HTTP-Redirect binding) |
| POST | `/saml/{provider}/acs` | No | Assertion Consumer Service (HTTP-POST binding) |
| GET | `/saml/{provider}/metadata` | No | SP metadata XML to import into the IdP |

## Flow

1. The browser visits the login endpoint, optionally with `redirect_uri`. The service builds an AuthnRequest, stores its ID as a single-use `saml_request` token with the continuation, and sends the ID as `RelayState`.
2. The handler sets an HttpOnly `goauth_saml_{connection}` binding cookie holding the request ID. The ACS is a cross-site POST, so the cookie is `SameSite=None; Secure`. On plain-HTTP development setups (`AllowInsecureCookies`) the attribute is omitted, which relies on the browser's two-minute Lax-by-default POST exception; a local Keycloak on another `localhost` port is same-site and unaffected.
3. The IdP posts `SAMLResponse` and `RelayState` to the ACS. The cookie must match `RelayState` in constant time, the stored request is consumed atomically (one response per request), and the library is given exactly that request ID for the `InResponseTo` check.
4. Signature, issuer, audience, destination and validity window are verified. The detailed cause of a rejection is logged and never returned to the client (`SAML_INVALID_RESPONSE`).
5. Account lookup, link or create runs with transaction-bound Core and account stores.
6. The common completer checks eligibility and additional-factor policy, then issues the selected grant. A pending challenge returns JSON `data.challenges`; otherwise the response is a redirect with tokens in the fragment, a cookie-only redirect in cookie auth mode, or JSON when no redirect URL is set.

**A local path is a first-party page.** When `redirect_uri` is a path on this server, such as `/admin/login/done?next=%2Fadmin` (the [admin console](./ui) uses this), the callback sets the credential cookies and redirects there with no tokens in the URL, whatever the auth mode. The path must start with a single `/` and contain no `//`, backslash, dot segments or fragment. If the sign-in still needs another factor, no credentials are set and the page receives `error=challenge_required`; when the auth mode does not allow cookies, it receives `error=cookies_disabled`. Absolute URLs behave as before.

A response without `RelayState` is IdP-initiated. It is rejected unless the connection sets `AllowIDPInitiated`; such logins have no browser binding and rely solely on the assertion's validity window, so keep it off unless the IdP needs it.

## Identity Resolution

1. A subject already linked under `(connection, NameID)` signs in, provided the stored issuer matches the IdP's entity ID.
2. Otherwise an existing user with the released email is used when `AllowAccountLinking` and `TrustEmail` are on, and the subject is linked.
3. Otherwise a user is created when `AllowSignup` is on. An email is required, and a transient NameID is refused because it cannot identify the user next time.

Stored identity: connection name, NameID, type `saml`, IdP entity ID as issuer, realm `default`.

## Keycloak Quick Start

1. Create a realm (for example `demo`) and a user with an email.
2. Clients → Create client → type **SAML**, Client ID = the SP entity ID, which defaults to `{APIURL}{BasePath}/saml/keycloak/metadata`. Alternatively Clients → Import client and upload the document served at that URL; it carries the ACS URL and the SP certificate.
3. In the client settings set **Name ID format** to `persistent` (or match `NameIDFormat`), enable **Sign documents** or **Sign assertions**, and leave **Client signature required** on with `SignRequests: true` (or turn it off and leave `SignRequests` false). **Encrypt assertions** works when `SPCertificate` is set.
4. Under Client scopes → the client's dedicated scope → Mappers, add **User Property** mappers for `email`, `firstName` and `lastName` (SAML attribute names `email`, `firstName`, `lastName`), or use the X500 mappers; both naming schemes are recognized.
5. Set `MetadataURL` to `{keycloak}/realms/demo/protocol/saml/descriptor`.
6. Visit `{APIURL}{BasePath}/saml/keycloak/login` and sign in at Keycloak.

Generate a development SP key pair with:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=goauth-sp" -keyout sp.key -out sp.crt
```

## Custom Connections

`saml.NewWithProviders(cfg, []saml.ServiceProvider)` installs trusted in-process connections before initialization, for hosts that load IdP metadata themselves or need a different protocol adapter. An implementation must verify the response completely before returning a `saml.Identity`. Registration is frozen after `Initialize()`.

## Events and Errors

The service emits `EventAfterSAMLLogin` with `SAMLLoginEventData` (user, connection, NameID, issuer, released attributes), `EventSAMLLinkAdded` when a subject is linked, and `EventAfterSignup` when a user is created.

Error codes: `SAML_PROVIDER_NOT_FOUND`, `SAML_INVALID_REQUEST`, `SAML_REQUEST_EXPIRED`, `SAML_INVALID_RESPONSE`, `SAML_IDP_INITIATED_DISABLED`, `SAML_SIGNUP_DISABLED`, `SAML_EMAIL_REQUIRED`, `SAML_ACCOUNT_LINKING_DISABLED`, `SAML_SUBJECT_NOT_PERSISTENT`.
