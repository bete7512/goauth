# @goauth/client

Typed TypeScript client for the GoAuth authentication library, generated from the same OpenAPI specs that ship embedded in each Go module.

## Regenerating

From the repo root:

```bash
make sdk
```

This runs two steps:

1. `clients/ts/scripts/merge-openapi.go` — walks `internal/modules/*/docs/openapi.yml`, merges paths + components, writes the combined spec to `clients/ts/openapi.yml`.
2. `npm run generate` (inside `clients/ts/`) — invokes `@hey-api/openapi-ts` to emit TypeScript types + fetch-based SDK into `src/generated/`.

Both the merged spec (`openapi.yml`) and the generated sources (`src/generated/`) are gitignored — they are rebuilt on demand.

## Layout

```
clients/ts/
├── scripts/
│   └── merge-openapi.go      # Builds the merged spec
├── src/
│   ├── index.ts              # Re-exports the generated SDK
│   └── generated/            # (generated) types + client
├── openapi-ts.config.ts      # @hey-api/openapi-ts config
├── openapi.yml               # (generated) merged OpenAPI spec
├── package.json
└── tsconfig.json
```

## Path collision note

Session and Stateless modules both define `/login`, `/logout`, and `/refresh` because only one is active at runtime. The merge script warns and keeps the alphabetically-later file — in practice, the Stateless variants (the library's default). Deployments using the Session module may prefer to regenerate the spec with `internal/modules/stateless/docs/openapi.yml` excluded.
