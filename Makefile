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

# Lint (requires golangci-lint)
lint:
	golangci-lint run ./...

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
