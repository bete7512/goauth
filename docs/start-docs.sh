#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v node >/dev/null || [ "$(node -p 'Number(process.versions.node.split(".")[0])')" -lt 22 ]; then
  echo "Node.js 22+ is required. Run nvm use in docs/ first."
  exit 1
fi
if [ ! -d node_modules/next ]; then
  npm ci
fi
exec npm run dev -- "$@"
