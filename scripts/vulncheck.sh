#!/usr/bin/env bash
# Runs govulncheck and fails on any vulnerability reachable from GoAuth's code,
# except the reviewed entries in scripts/vulncheck.allow.
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp)
trap 'rm -f "$out"' EXIT
govulncheck -format json ./... > "$out"

allowed=$(grep -oE '^GO-[0-9]{4}-[0-9]+' scripts/vulncheck.allow || true)
reachable=$(jq -r 'select(.finding != null and .finding.trace[0].function != null) | .finding.osv' "$out" | sort -u)

failed=0
for id in $reachable; do
	if grep -qxF "$id" <<< "$allowed"; then
		echo "allowed: $id (see scripts/vulncheck.allow)"
	else
		echo "vulnerable: $id https://pkg.go.dev/vuln/$id"
		failed=1
	fi
done
if [ "$failed" -ne 0 ]; then
	echo "Run 'govulncheck ./...' for traces." >&2
	exit 1
fi
echo "No unreviewed reachable vulnerabilities."
