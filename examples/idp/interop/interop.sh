#!/usr/bin/env bash
# Signs a user in to a real OpenID Connect client through the example
# identity provider, the way a browser would, and checks that the client
# ends up with a session for that user.
#
#   ./interop.sh grafana        # Grafana, generic OAuth
#   ./interop.sh oauth2-proxy   # oauth2-proxy, OIDC provider with discovery
#
# Needs docker (with host networking, so Linux), curl and python3. The
# example runs on PORT (default 18080); the client runs in a container that
# is removed afterwards.
set -euo pipefail

client=${1:-grafana}
port=${PORT:-18080}
origin="http://localhost:$port"
issuer="$origin/auth/oidc"
secret="interop-client-secret-0123456789abcdef0123"
email="ada@example.com"
password="correct-horse-battery"
container="goauth-idp-interop-$client"
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
jar="$work/cookies"

case "$client" in
  grafana)      client_url="http://localhost:33000"; callback="$client_url/login/generic_oauth" ;;
  oauth2-proxy) client_url="http://localhost:44180"; callback="$client_url/oauth2/callback" ;;
  *) echo "usage: $0 grafana|oauth2-proxy" >&2; exit 2 ;;
esac

cleanup() {
  status=$?
  docker rm -f "$container" >/dev/null 2>&1 || true
  [ -n "${example_pid:-}" ] && kill "$example_pid" >/dev/null 2>&1 || true
  if [ $status -ne 0 ]; then
    echo "--- example log ---" >&2; tail -n 20 "$work/example.log" >&2 || true
    echo "--- client log ---" >&2; tail -n 30 "$work/client.log" >&2 || true
  fi
  rm -rf "$work"
  exit $status
}
trap cleanup EXIT

json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
query() { python3 -c "import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query).get(sys.argv[2],[''])[0])" "$1" "$2"; }
wait_for() {
  for _ in $(seq 1 90); do
    curl -fsS -o /dev/null "$1" 2>/dev/null && return 0
    sleep 1
  done
  echo "timed out waiting for $1" >&2; return 1
}
step() { echo "==> $*"; }

step "starting the example identity provider on $origin"
(cd "$here/../.." && go build -o "$work/idp-example" ./idp)
PORT=$port CLIENT_SECRET=$secret REDIRECT_URIS=$callback REQUIRE_PKCE=1 "$work/idp-example" >"$work/example.log" 2>&1 &
example_pid=$!
wait_for "$issuer/.well-known/openid-configuration"

step "starting $client"
docker rm -f "$container" >/dev/null 2>&1 || true
case "$client" in
  grafana)
    docker run -d --name "$container" --network host \
      -e GF_SERVER_HTTP_PORT=33000 -e GF_SERVER_ROOT_URL="$client_url" \
      -e GF_AUTH_GENERIC_OAUTH_ENABLED=true -e GF_AUTH_GENERIC_OAUTH_NAME=GoAuth \
      -e GF_AUTH_GENERIC_OAUTH_CLIENT_ID=demo-app -e GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET="$secret" \
      -e GF_AUTH_GENERIC_OAUTH_SCOPES="openid profile email" \
      -e GF_AUTH_GENERIC_OAUTH_AUTH_URL="$issuer/authorize" \
      -e GF_AUTH_GENERIC_OAUTH_TOKEN_URL="$issuer/token" \
      -e GF_AUTH_GENERIC_OAUTH_API_URL="$issuer/userinfo" \
      -e GF_AUTH_GENERIC_OAUTH_USE_PKCE=true -e GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true \
      "${GRAFANA_IMAGE:-grafana/grafana:11.4.0}" >/dev/null
    start_url="$client_url/login/generic_oauth"
    wait_for "$client_url/api/health"
    ;;
  oauth2-proxy)
    docker run -d --name "$container" --network host \
      "${OAUTH2_PROXY_IMAGE:-quay.io/oauth2-proxy/oauth2-proxy:v7.6.0}" \
      --provider=oidc --oidc-issuer-url="$issuer" \
      --client-id=demo-app --client-secret="$secret" \
      --redirect-url="$callback" --http-address=127.0.0.1:44180 \
      --cookie-secret="$(python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')" \
      --cookie-secure=false --email-domain='*' --upstream=static://200 \
      --skip-provider-button=true --code-challenge-method=S256 \
      --insecure-oidc-allow-unverified-email=true >/dev/null
    start_url="$client_url/oauth2/start?rd=/"
    wait_for "$client_url/ping"
    ;;
esac
(docker logs -f "$container" >"$work/client.log" 2>&1 &)

step "the user has an account at the identity provider"
curl -fsS -o /dev/null -X POST "$origin/auth/signup" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$email\",\"password\":\"$password\",\"name\":\"Ada Lovelace\"}"
token=$(curl -fsS -X POST "$origin/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$email\",\"password\":\"$password\"}" | json "['data']['access_token']")

step "the client sends the browser to the identity provider"
authorize=$(curl -sS -c "$jar" -o /dev/null -w '%{redirect_url}' "$start_url")
case "$authorize" in "$issuer/authorize"*) ;; *) echo "unexpected redirect: $authorize" >&2; exit 1 ;; esac
[ -n "$(query "$authorize" code_challenge)" ] || { echo "the client sent no PKCE challenge" >&2; exit 1; }

step "the identity provider sends the browser to the consent page"
consent=$(curl -sS -o /dev/null -w '%{redirect_url}' "$authorize")
request_id=$(query "$consent" request_id)
[ -n "$request_id" ] || { echo "no request_id in: $consent" >&2; exit 1; }
details=$(curl -fsS -H "Authorization: Bearer $token" "$origin/auth/oidc/consent/$request_id")
echo "    asks for: $(echo "$details" | json "['data']['client']['name']"), scopes $(echo "$details" | python3 -c "import json,sys; print(' '.join(s['name'] for s in json.load(sys.stdin)['data']['scopes']))")"

step "the user approves"
back=$(curl -fsS -X POST -H "Authorization: Bearer $token" "$origin/auth/oidc/consent/$request_id/approve" | json "['data']['redirect_to']")
case "$back" in "$callback"*) ;; *) echo "unexpected redirect: $back" >&2; exit 1 ;; esac

step "the browser returns to the client, which redeems the code"
landed=$(curl -sS -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' "$back")
[ "$landed" = 302 ] || { echo "the client answered $landed to the callback" >&2; exit 1; }

step "the client has a session for the user"
case "$client" in
  grafana)      who=$(curl -fsS -b "$jar" "$client_url/api/user" | json "['email']") ;;
  oauth2-proxy) who=$(curl -fsS -b "$jar" "$client_url/oauth2/userinfo" | json "['email']") ;;
esac
[ "$who" = "$email" ] || { echo "signed in as '$who', expected '$email'" >&2; exit 1; }

echo "PASS: $client signed $who in through $issuer"
