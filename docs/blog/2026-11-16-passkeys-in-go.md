---
slug: passkeys-in-go
title: How to Add Passkeys (WebAuthn) to a Go App
description: Add passkeys to a Go app with WebAuthn and GoAuth. Register a passkey for a signed-in user, then sign in without a password, with working Go and JS code.
keywords: ["golang passkeys", "go webauthn", "passkeys in go", "webauthn golang tutorial", "passwordless login go", "add passkeys to go app"]
authors: [goauth-team]
tags: [passkeys, webauthn, go, authentication, tutorial]
---

# How to Add Passkeys (WebAuthn) to a Go App

Passkeys let people sign in with a fingerprint, a face scan or a security key instead of a password. This guide adds passkeys to a Go (Golang) server with GoAuth's passkeys module, which handles the WebAuthn ceremonies, stores the credentials and issues the same tokens as a password login.

<!-- truncate -->

## What you will build

A Go server where a user can:

1. Create an account and sign in with a password.
2. Register a passkey on that account.
3. Sign out and sign back in with only the passkey.

The passkeys module is **experimental**: it works and is tested, but its API and schema may change during the beta.

## Prerequisites

- Go 1.26 or later, and a C compiler for the SQLite driver.
- A browser with WebAuthn support (any current one) and a platform authenticator or security key.
- The project from the [Quick Start](/docs/quickstart). This guide adds to it.

## Step 1: Register the module

Add the passkeys module before `Initialize`. The relying party ID (`RPID`) is the domain your users see, with no scheme or port. `RPOrigins` lists the exact origins the browser ceremony may come from.

```go
import "github.com/bete7512/goauth/pkg/modules/passkeys"

// after auth.New, before a.Initialize
if err := a.Use(passkeys.New(&passkeys.Config{
    RPDisplayName: "Hello Passkeys",
    RPID:          "localhost",
    RPOrigins:     []string{"http://localhost:8080"},
})); err != nil {
    return err
}
```

`passkeys.Config` is an alias of `config.PasskeysModuleConfig`. `Initialize` fails if `RPID` is empty or no origin is given. `RPDisplayName` defaults to `GoAuth`.

For local work, `localhost` over plain HTTP is allowed by browsers. In production use your real domain, for example `RPID: "example.com"` with `RPOrigins: []string{"https://app.example.com"}`. Pick the RP ID carefully: authenticators tie each passkey to it, so changing it later makes existing passkeys unusable.

Serve a page from the same origin so the browser can run the ceremony:

```go
mux := http.NewServeMux()
mux.Handle("GET /", http.FileServer(http.Dir("public")))
return http.ListenAndServe(":8080", stdhttp.Register(mux, a))
```

With `Migration.Auto` on, the passkey table is created at startup. The built-in GORM storage supports PostgreSQL, MySQL and SQLite.

## Step 2: The endpoints you get

All paths are under `BasePath` (`/auth` here).

| Method | Path | Needs sign-in | Purpose |
| --- | --- | --- | --- |
| POST | `/passkeys/register/begin` | Yes | Creation options and a challenge token |
| POST | `/passkeys/register/finish` | Yes | Verify and save the new passkey |
| POST | `/passkeys/login/begin` | No | Request options for sign-in |
| POST | `/passkeys/login/finish` | No | Verify the assertion and sign in |
| GET | `/passkeys` | Yes | List the user's passkeys |
| PUT | `/passkeys/{id}` | Yes | Rename one |
| DELETE | `/passkeys/{id}` | Yes | Delete one |

Responses use the GoAuth envelope, so the useful part is under `data`.

## Step 3: Register a passkey in the browser

WebAuthn works with binary values. GoAuth sends and expects them as base64url strings inside JSON, so the page converts in both directions. Put this in `public/passkeys.js`:

```js
const b64urlToBuf = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
};
const bufToB64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const post = (path, body, token) =>
  fetch(`/auth${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body ?? {}),
  }).then((r) => r.json());

// accessToken comes from a normal POST /auth/login.
async function registerPasskey(accessToken) {
  const { data } = await post("/passkeys/register/begin", null, accessToken);
  const options = data.public_key;
  options.challenge = b64urlToBuf(options.challenge);
  options.user.id = b64urlToBuf(options.user.id);
  (options.excludeCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));

  const cred = await navigator.credentials.create({ publicKey: options });

  return post("/passkeys/register/finish", {
    challenge_token: data.challenge_token,
    name: "My laptop",
    credential_response: {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
      },
    },
  }, accessToken);
}
```

`credential_response` must be a JSON object, not a JSON-encoded string. Passkeys are added to an existing account; the module does not create accounts.

## Step 4: Sign in with the passkey

Sign-in is discoverable: the user does not type an email. The browser shows the passkeys it holds for this RP ID.

```js
async function signInWithPasskey() {
  const { data } = await post("/passkeys/login/begin");
  const options = data.public_key;
  options.challenge = b64urlToBuf(options.challenge);
  (options.allowCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));

  const cred = await navigator.credentials.get({ publicKey: options });
  const r = cred.response;

  const result = await post("/passkeys/login/finish", {
    challenge_token: data.challenge_token,
    credential_response: {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
        userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
      },
    },
  });

  if (result.data.challenges) {
    // A second step, such as a TOTP code, is still required.
    return result;
  }
  return result.data; // access_token, refresh_token, user
}
```

A successful answer has the same shape as `POST /auth/login`. With the default `AuthMode` the credential cookies are set as well.

## How the flow works

1. **Begin.** The server builds WebAuthn options and a random challenge. The WebAuthn session data is encrypted into the opaque `challenge_token`, and a purpose-bound record is stored as a digest.
2. **Browser.** The authenticator signs the challenge with a private key that never leaves the device.
3. **Finish.** The server consumes the one-time record first, then verifies the response against the configured RP ID and origins. A finish that fails needs a new begin.
4. **Completion.** A verified sign-in goes through the same completion path as a password login. Account policy, bans, the session or JWT strategy and two-factor rules all still apply.

## Security notes

- **Origins are exact.** A response from an origin not in `RPOrigins` is refused. List every frontend origin you use.
- **No replay.** Each challenge works once and expires within five minutes. The `ChallengeTTL` field exists but the current implementation does not apply a custom value.
- **Cloned authenticators.** The signature counter is checked; a non-increasing nonzero counter is rejected. Authenticators that report zero are allowed.
- **Two-factor still applies.** A passkey does not skip a configured TOTP requirement. Handle `data.challenges` in the client.
- **Shared storage.** Begin and finish can land on different replicas, so all instances need the same database.

## Next steps

- [Passkeys module reference](/docs/modules/passkeys)
- [Two-Factor module](/docs/modules/twofactor), to combine passkeys with TOTP
- [Security guide](/docs/security) for cookies, tokens and keys
- [Production checklist](/docs/production) before real users sign in
