# GoAuth Tests

This directory contains all tests for the GoAuth library, organized by type and component.

## 📁 Directory Structure

```
tests/
├── unit/                    # Unit tests
│   ├── api/
│   │   └── handlers/        # API handler unit tests
│   ├── repositories/
│   │   └── postgres/        # Repository unit tests
│   ├── hooks/               # Hook system tests
│   └── tokens/              # Token manager tests
├── integration/             # Integration tests
│   ├── api/                 # API integration tests
│   └── repositories/        # Database integration tests
├── benchmarks/              # Performance benchmarks
│   ├── api/                 # API handler benchmarks
│   └── repositories/        # Repository benchmarks
├── test_config.go           # Test configuration
├── test_utils.go            # Test utilities
└── README.md                # This file
```

## 🧪 Test Types

### Unit Tests (`unit/`)
- **Purpose**: Test individual functions and methods in isolation
- **Scope**: Single package or function
- **Dependencies**: Mocked or minimal dependencies
- **Speed**: Fast execution

### Integration Tests (`integration/`)
- **Purpose**: Test interactions between components
- **Scope**: Multiple packages working together
- **Dependencies**: Real database, external services
- **Speed**: Slower execution

### Benchmark Tests (`benchmarks/`)
- **Purpose**: Measure performance and identify bottlenecks
- **Scope**: Critical code paths
- **Dependencies**: Real or mocked as needed
- **Speed**: Performance-focused

## 🚀 Running Tests

### Run All Tests
```bash
go test ./tests/...
```

### Run Unit Tests Only
```bash
go test ./tests/unit/...
```

### Run Integration Tests Only
```bash
go test ./tests/integration/...
```

### Run Benchmark Tests
```bash
go test -bench=. ./tests/benchmarks/...
```

### Run Specific Test Package
```bash
go test ./tests/unit/api/handlers
go test ./tests/unit/repositories/postgres
```

### Run with Coverage
```bash
go test -cover ./tests/...
go test -coverprofile=coverage.out ./tests/...
go tool cover -html=coverage.out
```

### Run with Verbose Output
```bash
go test -v ./tests/...
```

## 📋 Test Configuration

### Test Configuration (`test_config.go`)
- Provides a standardized test configuration
- Uses in-memory SQLite for fast tests
- Disables external services (email, SMS, etc.)
- Uses test-specific secrets and settings

### Test Utilities (`test_utils.go`)
- Common test helper functions
- HTTP request/response creation
- Test data generation
- Auth service setup

## 🎯 Writing Tests

### Unit Test Example
```go
package handlers

import (
    "testing"
    "net/http"
    "net/http/httptest"
    
    "github.com/stretchr/testify/assert"
    "github.com/bete7512/goauth/tests"
)

func TestRegisterHandler(t *testing.T) {
    // Setup
    testUtils, err := tests.NewTestUtils()
    assert.NoError(t, err)
    
    // Test data
    userData := tests.GetTestUserData()
    
    // Create request
    req := testUtils.CreateTestRequest("POST", "/auth/register", userData)
    w := testUtils.CreateTestResponse()
    
    // Execute
    // TODO: Add actual handler call
    
    // Assert
    assert.Equal(t, http.StatusOK, w.Code)
}
```

### Integration Test Example
```go
package api

import (
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/bete7512/goauth/tests"
)

func TestFullAuthFlow(t *testing.T) {
    // Setup
    testUtils, err := tests.NewTestUtils()
    assert.NoError(t, err)
    
    // Test complete auth flow
    t.Run("Register User", func(t *testing.T) {
        // TODO: Implement registration test
    })
    
    t.Run("Login User", func(t *testing.T) {
        // TODO: Implement login test
    })
    
    t.Run("Access Protected Endpoint", func(t *testing.T) {
        // TODO: Implement protected endpoint test
    })
}
```

### Benchmark Test Example
```go
package api

import (
    "testing"
    
    "github.com/bete7512/goauth/tests"
)

func BenchmarkRegisterHandler(b *testing.B) {
    testUtils, err := tests.NewTestUtils()
    if err != nil {
        b.Fatal(err)
    }
    
    userData := tests.GetTestUserData()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        req := testUtils.CreateTestRequest("POST", "/auth/register", userData)
        w := testUtils.CreateTestResponse()
        
        // TODO: Add actual handler benchmark
        _ = req
        _ = w
    }
}
```

## 🔧 Test Dependencies

### Required Dependencies
- `github.com/stretchr/testify/assert` - Assertions
- `github.com/stretchr/testify/require` - Required assertions
- `github.com/stretchr/testify/mock` - Mocking
- `github.com/stretchr/testify/suite` - Test suites

### Database Dependencies
- SQLite (in-memory) for unit tests
- PostgreSQL/MySQL for integration tests
- Test database setup scripts

## 📊 Test Coverage

### Coverage Goals
- **Unit Tests**: 90%+ coverage
- **Integration Tests**: Critical paths covered
- **Benchmark Tests**: Performance-critical functions

### Coverage Reports
```bash
# Generate coverage report
go test -coverprofile=coverage.out ./tests/...

# View HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# View coverage summary
go tool cover -func=coverage.out
```

## 🐛 Debugging Tests

### Verbose Output
```bash
go test -v ./tests/unit/api/handlers
```

### Run Single Test
```bash
go test -run TestRegisterHandler ./tests/unit/api/handlers
```

### Debug with Delve
```bash
dlv test ./tests/unit/api/handlers
```

## 📝 Test Guidelines

### Naming Conventions
- Test files: `*_test.go`
- Test functions: `TestFunctionName`
- Benchmark functions: `BenchmarkFunctionName`
- Test packages: Same as source package

### Test Structure
1. **Setup**: Initialize test dependencies
2. **Execute**: Run the code being tested
3. **Assert**: Verify the results
4. **Cleanup**: Clean up resources

### Best Practices
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Use table-driven tests for multiple scenarios
- Keep tests fast and independent
- Use subtests for better organization

## 🔄 Continuous Integration

### CI Pipeline
- Run unit tests on every commit
- Run integration tests on pull requests
- Run benchmarks on releases
- Generate coverage reports

### Test Commands for CI
```bash
# Install dependencies
go mod download

# Run tests
go test -v -race -cover ./tests/...

# Run benchmarks
go test -bench=. -benchmem ./tests/benchmarks/...

# Generate coverage
go test -coverprofile=coverage.out ./tests/...
```

## 📚 Additional Resources

- [Go Testing Package](https://golang.org/pkg/testing/)
- [Testify Documentation](https://github.com/stretchr/testify)
- [Go Testing Best Practices](https://golang.org/doc/tutorial/add-a-test) 