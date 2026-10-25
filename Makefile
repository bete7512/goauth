.PHONY: mocks test test-unit test-integration test-coverage test-bench lint build clean sdk sdk-spec

# Generate all mocks via go:generate directives
mocks:
	go generate ./...

fmt:
	go fmt ./...
# Run all unit tests (excludes integration)
test: test-unit

test-unit:
	go test ./... -count=1

# Run tests with verbose output
test-verbose:
	go test ./... -v -count=1

# Run integration tests (requires running database)
test-integration:
	go test -tags=integration ./tests/integration/ -v -count=1

# Run tests with coverage report
test-coverage:
	go test ./... -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out

# Run tests with HTML coverage report
test-coverage-html: test-coverage
	go tool cover -html=coverage.out -o coverage.html

# Build
build:
	go build ./...

# Lint (requires golangci-lint v2; config in .golangci.yml)
lint:
	golangci-lint run ./...

# Known vulnerabilities in reachable code (requires govulncheck)
.PHONY: vuln tidy-check generate-check check
vuln:
	govulncheck ./...

# Fails when go.mod/go.sum of the root or nested modules need tidying
tidy-check:
	go mod tidy -diff
	@for module in examples pkg/adapters/chiadapter pkg/adapters/ginadapter pkg/adapters/fiberadapter; do \
		(cd $$module && go mod tidy -diff) || exit 1; \
	done

# Fails when regenerated mocks differ from the committed ones
generate-check: mocks
	git diff --exit-code

# Everything CI checks except the database contract jobs
check: build lint vuln tidy-check generate-check test test-integration

# Run benchmarks
.PHONY: test-bench
test-bench:
	go test ./tests/benchmarks/ -bench=. -benchmem -count=3

# Clean generated files
clean:
	rm -f coverage.out coverage.html test_out.txt
	rm -rf clients/ts/openapi.yml clients/ts/src/generated clients/ts/node_modules clients/ts/dist

# Merge all module OpenAPI specs into clients/ts/openapi.yml
sdk-spec:
	go run ./clients/ts/scripts/merge-openapi.go

# Regenerate the TypeScript client SDK (@goauth/client).
# Requires npm; installs deps on first run.
sdk: sdk-spec
	cd clients/ts && (test -d node_modules || npm install) && npm run generate

# Storage contract tests against a disposable database container (requires docker).
.PHONY: test-contracts-mysql test-contracts-postgres
test-contracts-mysql:
	docker rm -f goauth-contracts-mysql >/dev/null 2>&1 || true
	docker run -d --name goauth-contracts-mysql -e MYSQL_DATABASE=goauth_contracts -e MYSQL_ROOT_PASSWORD=contract-password -p 127.0.0.1:33306:3306 mysql:8.4 >/dev/null
	@until docker exec goauth-contracts-mysql mysqladmin ping -h 127.0.0.1 -pcontract-password --silent >/dev/null 2>&1; do sleep 2; done; sleep 5
	GOAUTH_CONTRACT_DIALECT=mysql GOAUTH_CONTRACT_DSN='root:contract-password@tcp(127.0.0.1:33306)/goauth_contracts?parseTime=true&loc=UTC' go test -race ./storage/gorm -count=1; status=$$?; docker rm -f goauth-contracts-mysql >/dev/null; exit $$status

test-contracts-postgres:
	docker rm -f goauth-contracts-postgres >/dev/null 2>&1 || true
	docker run -d --name goauth-contracts-postgres -e POSTGRES_DB=goauth_contracts -e POSTGRES_USER=goauth -e POSTGRES_PASSWORD=contract-password -p 127.0.0.1:35432:5432 postgres:17 >/dev/null
	@until docker exec goauth-contracts-postgres pg_isready -U goauth -d goauth_contracts >/dev/null 2>&1; do sleep 2; done
	GOAUTH_CONTRACT_DIALECT=postgres GOAUTH_CONTRACT_DSN='host=127.0.0.1 user=goauth password=contract-password dbname=goauth_contracts port=35432 sslmode=disable' go test -race ./storage/gorm -count=1; status=$$?; docker rm -f goauth-contracts-postgres >/dev/null; exit $$status
