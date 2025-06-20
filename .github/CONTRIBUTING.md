# Contributing to GoAuth

Thank you for your interest in contributing to GoAuth! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for using the Makefile)

### Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/goauth.git
   cd goauth
   ```

2. **Install development tools:**
   ```bash
   make install-tools
   # or manually:
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
   go install golang.org/x/vuln/cmd/govulncheck@latest
   go install github.com/swaggo/swag/cmd/swag@latest
   ```

3. **Download dependencies:**
   ```bash
   make deps
   # or:
   go mod download
   ```

## Making Changes

### Code Style

- Follow Go formatting standards (`gofmt -s`)
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions small and focused
- Follow Go naming conventions

### Project Structure

```
goauth/
├── api/           # API layer and framework adapters
├── database/      # Database client and connections
├── hooks/         # Hook system
├── interfaces/    # Interface definitions
├── logger/        # Logging utilities
├── models/        # Data models
├── ratelimiter/   # Rate limiting
├── recaptcha/     # reCAPTCHA integration
├── repositories/  # Data access layer
├── schemas/       # Database schemas
├── tokens/        # Token management
├── types/         # Type definitions
├── utils/         # Utility functions
└── examples/      # Usage examples
```

### Adding New Features

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Add new code in appropriate directories
   - Update tests
   - Update documentation

3. **Run tests:**
   ```bash
   make test-all
   ```

4. **Check code quality:**
   ```bash
   make quality
   ```

## Testing

### Running Tests

```bash
# Run all tests
make test-all

# Run only unit tests
make test

# Run integration tests
make test-integration

# Run benchmarks
make test-benchmark

# Run tests with coverage
make test-coverage
```

### Writing Tests

- Write tests for all new functionality
- Use descriptive test names
- Follow the pattern: `TestFunctionName_Scenario_ExpectedResult`
- Use table-driven tests when appropriate
- Mock external dependencies

### Test Structure

```go
func TestFunctionName_Scenario_ExpectedResult(t *testing.T) {
    // Arrange
    // Set up test data and mocks
    
    // Act
    // Call the function being tested
    
    // Assert
    // Verify the results
}
```

## Submitting Changes

### Before Submitting

1. **Run all checks:**
   ```bash
   make check
   ```

2. **Ensure tests pass:**
   ```bash
   make test-all
   ```

3. **Check code quality:**
   ```bash
   make quality
   ```

### Creating a Pull Request

1. **Push your changes:**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a pull request:**
   - Use the provided PR template
   - Describe your changes clearly
   - Link any related issues
   - Include test results if applicable

3. **Wait for review:**
   - Address any feedback
   - Make requested changes
   - Re-request review when ready

## Release Process

### Creating a Release

1. **Prepare for release:**
   ```bash
   make prepare
   ```

2. **Create a release tag:**
   ```bash
   make release-tag
   # or manually:
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **GitHub Actions will automatically:**
   - Run all tests
   - Generate documentation
   - Create a GitHub release
   - Upload artifacts

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

## Getting Help

- **Issues:** Use GitHub issues for bug reports and feature requests
- **Discussions:** Use GitHub Discussions for questions and general discussion
- **Documentation:** Check the README and inline documentation

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- GitHub contributors page

Thank you for contributing to GoAuth! 🚀 