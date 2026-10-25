# Contributing to GoAuth

Thanks for helping. This guide covers the setup, the checks CI runs, and the conventions the codebase follows. Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Setup

| Tool | Needed for |
| --- | --- |
| Go 1.26+ | everything |
| [golangci-lint](https://golangci-lint.run/) v2 | `make lint` |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | `make vuln` |
| mockgen v0.6.0 (`go install go.uber.org/mock/mockgen@v0.6.0`) | `make mocks` |
| Node 22 | only the TypeScript client (`make sdk`) |
| Docker | only the database contract tests |

## Checks

| Command | What it runs |
| --- | --- |
| `make build` | compile every package |
| `make test` | unit tests |
| `make test-integration` | the integration suite on in-memory SQLite |
| `make lint` | golangci-lint with `.golangci.yml` |
| `make vuln` | govulncheck on reachable code |
| `make tidy-check` | `go mod tidy -diff` for the root and nested modules |
| `make generate-check` | regenerates mocks and fails on drift |
| `make sdk-spec` | rebuilds `clients/ts/openapi.yml` from the module specs |
| `make test-contracts-postgres`, `make test-contracts-mysql` | storage contract tests in a disposable container |
| `make check` | everything above except the contract tests |

CI runs `make check` equivalents plus the Postgres and MySQL contract jobs on every pull request.

## Conventions

- **Lifecycle:** `auth.New(config)`, then `Use(module)`, then `Initialize(ctx)`. The core module is registered automatically.
- **Public API:** external code imports `pkg/...` only. Bundled modules are exposed through thin proxies in `pkg/modules/<name>`; never leak `internal/` types into `pkg/`.
- **Modules** live in `internal/modules/<name>` with `module.go`, `handlers/`, `services/` and `docs/openapi.yml`, and declare `var _ config.Module = (*XModule)(nil)`. Module names use the `types.XModule` constants.
- **Services** are an exported interface with an unexported implementation, return `*types.GoAuthError`, and carry a `//go:generate mockgen` directive. Handlers depend on the interface.
- **Errors** use the `types.Err*` codes: `http_utils.RespondError(w, status, string(types.ErrXxx), msg)`.
- **OpenAPI:** any change to an endpoint or DTO updates the module's `docs/openapi.yml`; run `make sdk-spec` and commit `clients/ts/openapi.yml`.
- **Routes** are named with dots (`core.login`); **IDs** are UUIDv7; **logging** goes through `deps.Logger`, never `fmt.Printf`, and never logs secrets.
- **Tests** use testify suites and gomock. Integration helpers live in `tests/integration/testhelpers`. Single-use secrets are stored as digests, so tests read links and codes from delivery events (`RecordEvents`), not from the database.
- **Security fixes** come with a regression test that fails before the fix.

## Pull requests

- One issue per pull request, with `Closes #N` in the description.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md); breaking changes go first, with the migration step.
- Keep CI green: `test`, `lint` and both database contract jobs.

## Releases

1. Make sure CI is green on `main`.
2. Move the `Unreleased` entries under a heading for the new version and date.
3. Set the `github.com/bete7512/goauth` requirement in each `pkg/adapters/*/go.mod` to the new version (their `replace` keeps local builds on the checkout).
4. Tag the root module and each adapter module on the same `main` commit, then push the tags:
   ```
   V=v0.3.0-beta.1
   git tag $V
   for m in chiadapter ginadapter fiberadapter; do git tag pkg/adapters/$m/$V; done
   git push origin $V pkg/adapters/chiadapter/$V pkg/adapters/ginadapter/$V pkg/adapters/fiberadapter/$V
   ```
   The release workflow reruns the tests and publishes the GitHub release for the root tag; a tag with a hyphen is marked as a pre-release.
5. Check that the versions appear on [pkg.go.dev](https://pkg.go.dev/github.com/bete7512/goauth).

Never delete and re-push a published tag, and never reuse a version number: the Go module proxy and checksum database keep every published version permanently. Mark a bad version with a `retract` directive in `go.mod` instead.
