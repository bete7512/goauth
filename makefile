# GoAuth Library Makefile
# A comprehensive build system for the GoAuth authentication library

# Variables
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH=$(shell git rev-parse --short HEAD)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.CommitHash=${COMMIT_HASH}"

# Go related variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=gofmt
GOLINT=golangci-lint
GOSEC=gosec

# Directories
BUILD_DIR=build
DIST_DIR=dist
DOCS_DIR=docs
COVERAGE_DIR=coverage
EXAMPLES_DIR=examples

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
.PHONY: install-tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/swaggo/swag/cmd/swag@latest

# Build targets (for examples and testing)
.PHONY: build-examples
build-examples: ## Build example applications
	@echo "Building examples..."
	@mkdir -p $(BUILD_DIR)
	@if [ -d "$(EXAMPLES_DIR)" ]; then \
		for dir in $(EXAMPLES_DIR)/*; do \
			if [ -d "$$dir" ] && [ -f "$$dir/main.go" ]; then \
				echo "Building $$(basename $$dir)..."; \
				$(GOBUILD) -o $(BUILD_DIR)/$$(basename $$dir) $$dir; \
			fi; \
		done; \
	else \
		echo "No examples directory found"; \
	fi

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -rf $(COVERAGE_DIR)

# Test targets
.PHONY: test
test: ## Run unit tests
	@echo "Running unit tests..."
	$(GOTEST) -v -race ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated at $(COVERAGE_DIR)/coverage.html"

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration ./integration_test.go

.PHONY: test-benchmark
test-benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

.PHONY: test-all
test-all: test test-integration test-benchmark ## Run all tests

# Code quality targets
.PHONY: fmt
fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) -s -w .

.PHONY: fmt-check
fmt-check: ## Check code formatting
	@echo "Checking code formatting..."
	@if [ "$(shell $(GOFMT) -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted. Please run 'make fmt'"; \
		$(GOFMT) -s -l .; \
		exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...

.PHONY: lint
lint: ## Run linter
	@echo "Running linter..."
	$(GOLINT) run ./...

.PHONY: security
security: ## Run security scanner
	@echo "Running security scanner..."
	$(GOSEC) ./...

.PHONY: vulncheck
vulncheck: ## Check for vulnerabilities
	@echo "Checking for vulnerabilities..."
	govulncheck ./...

.PHONY: quality
quality: fmt-check vet lint security vulncheck ## Run all code quality checks

# Documentation targets
.PHONY: docs
docs: ## Generate documentation
	@echo "Generating documentation..."
	@mkdir -p $(DOCS_DIR)
	@if [ -f "cmd/goauth/main.go" ]; then \
		swag init -g cmd/goauth/main.go -o $(DOCS_DIR); \
	else \
		echo "No main.go found for Swagger generation"; \
	fi

.PHONY: docs-serve
docs-serve: docs ## Serve documentation locally
	@echo "Documentation generated in $(DOCS_DIR)/"

# Dependencies targets
.PHONY: deps
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	$(GOMOD) tidy
	$(GOMOD) download

.PHONY: deps-check
deps-check: ## Check for outdated dependencies
	@echo "Checking for outdated dependencies..."
	$(GOCMD) list -u -m all

# Release targets
.PHONY: release-tag
release-tag: ## Create and push a new release tag
	@echo "Creating release tag..."
	@read -p "Enter version (e.g., v1.0.0): " version; \
	git tag -a $$version -m "Release $$version"; \
	git push origin $$version

# CI/CD targets
.PHONY: ci
ci: quality test-all ## Run CI pipeline locally

.PHONY: pre-commit
pre-commit: fmt quality test ## Run pre-commit checks

# Utility targets
.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Commit Hash: $(COMMIT_HASH)"

.PHONY: info
info: ## Show build information
	@echo "Library Name: goauth"
	@echo "Version: $(VERSION)"
	@echo "Build Directory: $(BUILD_DIR)"
	@echo "Go Version: $(shell go version)"

# Development workflow
.PHONY: setup
setup: install-tools deps ## Setup development environment

.PHONY: check
check: quality test ## Run all checks

.PHONY: prepare
prepare: clean deps-update quality test-all ## Prepare for release

# Library-specific targets
.PHONY: validate
validate: ## Validate library structure and exports
	@echo "Validating library structure..."
	@if [ ! -f "goauth.go" ]; then \
		echo "Error: goauth.go not found"; \
		exit 1; \
	fi
	@echo "Library structure is valid"

.PHONY: examples
examples: build-examples ## Build and run examples
	@echo "Examples built successfully"

.PHONY: benchmark-report
benchmark-report: ## Generate benchmark report
	@echo "Generating benchmark report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -bench=. -benchmem -benchtime=1s ./... > $(COVERAGE_DIR)/benchmark.txt
	@echo "Benchmark report saved to $(COVERAGE_DIR)/benchmark.txt" 

.PHONY: security-scan
security-scan: ## Run security scan
	@echo "Running security scan..."
	gosec ./...

.PHONY: security-scan-report
security-scan-report: ## Generate security scan report
	 go run golang.org/x/vuln/cmd/govulncheck ./... -show verbose