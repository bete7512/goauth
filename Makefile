.PHONY: mocks test test-unit test-integration test-coverage test-bench lint build clean

# Generate all mocks via go:generate directives
mocks:
	go generate ./...

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
