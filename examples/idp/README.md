# Identity provider example

GoAuth as an OpenID Connect provider: another application signs users in with the accounts of this one. The identity provider module serves the page where the user signs in and approves, so the example is GoAuth and nothing else.

| Address | What it is |
| --- | --- |
| `http://localhost:8080/auth/oidc` | The issuer. A client is configured with this |
| `http://localhost:8080/auth/oidc/.well-known/openid-configuration` | Discovery document |
| `http://localhost:8080/auth/oidc/consent` | The page where the user signs in and approves the client, served by the module |

## Run it

From the `examples` directory:

```sh
go run ./idp
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8080` | Port to listen on; the issuer follows it |
| `CLIENT_SECRET` | a demo value | Secret of the client `demo-app`, at least 32 characters |
| `REDIRECT_URIS` | Grafana on 3000, oauth2-proxy on 4180 | Comma-separated redirect URIs of `demo-app` |
| `REQUIRE_PKCE` | unset | Set to any value to refuse sign-ins without PKCE |
| `OWN_PAGE` | unset | Set to any value to use the example's own consent page (`consent.html`, `consent.js`) at `/oidc/consent` instead of the module's |

The example creates one account to sign in with: `demo@example.com`, password `demo-password`. Users, grants and the signing key live in memory: the example forgets everything when it stops.

## Sign in with Grafana

Start Grafana next to the example (Linux, host networking):

```sh
docker run --rm --network host \
  -e GF_AUTH_GENERIC_OAUTH_ENABLED=true \
  -e GF_AUTH_GENERIC_OAUTH_NAME=GoAuth \
  -e GF_AUTH_GENERIC_OAUTH_CLIENT_ID=demo-app \
  -e GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=example-client-secret-change-me-0123456789 \
  -e GF_AUTH_GENERIC_OAUTH_SCOPES="openid profile email" \
  -e GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://localhost:8080/auth/oidc/authorize \
  -e GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://localhost:8080/auth/oidc/token \
  -e GF_AUTH_GENERIC_OAUTH_API_URL=http://localhost:8080/auth/oidc/userinfo \
  -e GF_AUTH_GENERIC_OAUTH_USE_PKCE=true \
  grafana/grafana:11.4.0
```

Open `http://localhost:3000`, choose **Sign in with GoAuth**, sign in as `demo@example.com` and continue. Grafana signs you in with that account.

## What happens

1. The client sends the browser to `/auth/oidc/authorize`.
2. GoAuth checks the client and its redirect URI, stores the request and redirects to its page, `/auth/oidc/consent?request_id=...`.
3. The page shows a sign-in form, unless the browser is signed in to the application already, and then the application and what it will learn. When there is nothing to ask it continues without a prompt.
4. **Continue** sends the browser to the client's redirect URI with a one-time code; **Cancel** sends it there with `access_denied`.
5. The client redeems the code at `/auth/oidc/token`, verifies the ID token against `/auth/oidc/jwks`, and may read `/auth/oidc/userinfo`.

## Checking it against real clients

`interop/interop.sh` runs the whole sign-in against a real client in a container, playing the browser with curl through the module's page, and checks that the client ends up with a session for the user:

```sh
./idp/interop/interop.sh grafana        # Grafana 11.4, generic OAuth with PKCE
./idp/interop/interop.sh oauth2-proxy   # oauth2-proxy 7.6, OIDC discovery, verifies the ID token signature
```

It needs Docker with host networking (Linux), curl and python3, starts the example on port 18080 and removes the container afterwards.

## Moving to your own application

- Keep the signing key stable and out of the repository; `openssl genrsa -out idp-signing-key.pem 2048`. A new key invalidates every ID token issued before.
- Serve the issuer over https. Plain http is accepted on loopback addresses only.
- Declare your clients in `IDPModuleConfig.Clients`, or set `AdminAPI: true` and register them through `/admin/oidc/clients`.
- Set `AppName` to what your users call your product; the page says whose account is being asked for.
- To keep the page in your own frontend instead, set `ConsentURL` and build it on the JSON endpoints, as `consent.html` and `consent.js` do (run the example with `OWN_PAGE=1`). If your application signs users in with cookies, register the CSRF module: the consent decision is then protected like any other request of the signed-in user.

See the [module documentation](../../docs/docs/modules/idp.md) for every option.
