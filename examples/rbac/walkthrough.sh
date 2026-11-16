#!/usr/bin/env bash
# Walks through every guard in internal/api/router.go against a running
# example (go run ./rbac). Needs curl and jq. Each line prints the HTTP
# status next to the status the guard should give.
set -euo pipefail
BASE=${BASE:-http://localhost:8080}
PASSWORD="Tracker-demo-1"
CAST=$(curl -fsS "$BASE/demo/cast")
id() { jq -r "$1" <<<"$CAST"; }
ACME=$(id .acme); GLOBEX=$(id .globex)
BACKEND=$(id '.teams.Backend'); MOBILE=$(id '.teams.Mobile'); DESIGN=$(id '.teams.Design')

# token NAME [ORG]: sign in, and into ORG when given.
token() {
  local t
  t=$(curl -fsS "$BASE/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1@tracker.test\",\"password\":\"$PASSWORD\"}" | jq -r .data.access_token)
  if [[ -n "${2:-}" ]]; then
    t=$(curl -fsS "$BASE/auth/org/switch" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' \
      -d "{\"org_id\":\"$2\"}" | jq -r .data.access_token)
  fi
  echo "$t"
}

# try WHO TOKEN METHOD PATH WANT [BODY]
pass=0; fail=0
try() {
  local args=(-s -o /dev/null -w '%{http_code}' -X "$3" "$BASE$4" -H "Authorization: Bearer $2" -H 'Content-Type: application/json')
  [[ -n "${6:-}" ]] && args+=(-d "$6")
  local got; got=$(curl "${args[@]}")
  if [[ "$got" == "$5" ]]; then pass=$((pass+1)); mark="ok  "; else fail=$((fail+1)); mark="FAIL"; fi
  printf '%s %-28s %-6s %-48s %s (want %s)\n' "$mark" "$1" "$3" "$4" "$got" "$5"
}

echo "1. Application-wide role (rbac.Global)"
try "sue, support" "$(token sue)" GET /api/reports/usage 200
try "alice, owns Acme" "$(token alice "$ACME")" GET /api/reports/usage 403

echo "2. The token's organization (Resource \"invoice\")"
HANK=$(token hank "$ACME"); CAROL=$(token carol "$ACME"); BOB=$(token bob "$ACME")
try "hank, billing" "$HANK" POST /api/invoices 201 '{"customer":"Wayne","amount_cents":1000}'
try "carol, accountant" "$CAROL" POST /api/invoices 403 '{"customer":"Wayne","amount_cents":1000}'
try "carol, accountant" "$CAROL" GET /api/invoices 200

echo "3. The invoice's organization + OnlyIf (four eyes)"
try "bob, admin, own invoice" "$BOB" POST "/api/invoices/$(id .bobs_invoice)/approve" 403
try "carol, accountant" "$CAROL" POST "/api/invoices/$(id .bobs_invoice)/approve" 200
try "carol, Globex invoice" "$CAROL" POST "/api/invoices/$(id .globex_invoice)/approve" 403

echo "4. The organization in the path (OrgParam)"
try "carol" "$CAROL" GET "/api/orgs/$ACME/billing" 200
try "carol" "$CAROL" GET "/api/orgs/$GLOBEX/billing" 403

echo "5. The team in the path (TeamParam); roles flow down"
DAVE=$(token dave "$ACME"); ERIN=$(token erin "$ACME"); FRANK=$(token frank "$ACME")
try "dave, lead of Engineering" "$DAVE" POST "/api/teams/$MOBILE/projects" 201 '{"name":"Android app"}'
try "dave, lead of Engineering" "$DAVE" POST "/api/teams/$DESIGN/projects" 403 '{"name":"Logo"}'
try "erin, developer on Backend" "$ERIN" GET "/api/teams/$BACKEND/projects" 200
try "erin, developer on Backend" "$ERIN" GET "/api/teams/$MOBILE/projects" 403

echo "6. The project's team (TeamFrom)"
try "erin" "$ERIN" PATCH "/api/projects/$(id .payments_api)" 200 '{"name":"Payments API v2"}'
try "frank, plain member" "$FRANK" GET "/api/projects/$(id .ios_app)" 403

echo "7. A list across teams (TeamsWhere)"
for who in erin dave alice; do
  t=$(token "$who" "$ACME")
  printf '     %-6s sees: %s\n' "$who" "$(curl -fsS "$BASE/api/projects" -H "Authorization: Bearer $t" | jq -c '[.projects[].name]')"
done

echo "8. A check in code (authz.Check + InTeam)"
try "erin, developer" "$ERIN" POST "/api/projects/$(id .payments_api)/archive" 403
try "dave, lead" "$DAVE" POST "/api/projects/$(id .payments_api)/archive" 200

echo "9. AllowIf: the assignee completes their own task"
try "frank, assignee" "$FRANK" POST "/api/tasks/$(id .franks_task)/complete" 200
try "erin, not in Mobile" "$ERIN" POST "/api/tasks/$(id .franks_task)/complete" 403

echo
echo "What each person holds: GET $BASE/auth/me/permissions (with their token)."
echo "$pass passed, $fail failed."
[[ $fail -eq 0 ]]
