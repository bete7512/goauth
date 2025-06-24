# GoAuth Library Restructuring

This document outlines the restructuring of the GoAuth library to follow Go project conventions and improve maintainability.

## 🏗️ New Structure

```
go-auth/
├── pkg/                   # Public API - what users import
│   ├── auth/              # Main library entry point
│   │   ├── auth.go        # Public AuthService interface
│   │   ├── builder.go     # Builder pattern
│   │   └── types.go       # Public types
│   ├── config/            # Configuration types
│   │   ├── config.go
│   │   ├── auth.go
│   │   ├── security.go
│   │   ├── providers.go
│   │   ├── notifications.go
│   │   ├── storage.go
│   │   ├── constants.go
│   │   └── common.type.go
│   └── types/             # Public types and interfaces
│       ├── common.go
│       └── types.go
├── internal/              # Private implementation
│   ├── auth/              # Core auth logic
│   ├── api/               # HTTP handlers
│   │   ├── handlers/
│   │   ├── middleware/
│   │   └── routes/
│   ├── database/          # Database layer
│   ├── repositories/      # Data access layer
│   ├── notifications/     # Email/SMS
│   ├── tokens/            # Token management
│   ├── ratelimiter/       # Rate limiting
│   ├── recaptcha/         # reCAPTCHA
│   ├── hooks/             # Hook system
│   ├── logger/            # Logging
│   ├── utils/             # Internal utilities
│   ├── interfaces/        # Internal interfaces
│   ├── schemas/           # Request/response schemas
│   ├── caches/            # Cache implementations
│   └── external/          # External service clients
├── examples/              # Usage examples
│   ├── basic/             # Basic usage
│   ├── frameworks/        # Framework examples
│   │   ├── gin/
│   │   ├── echo/
│   │   ├── chi/
│   │   └── fiber/
│   ├── oauth/             # OAuth examples
│   └── custom/            # Custom implementations
├── docs/                  # Documentation
├── tests/                 # Test files (reorganized)
│   ├── unit/              # Unit tests
│   │   ├── api/
│   │   │   └── handlers/  # API handler unit tests
│   │   ├── repositories/
│   │   │   └── postgres/  # Repository unit tests
│   │   ├── hooks/         # Hook system tests
│   │   └── tokens/        # Token manager tests
│   ├── integration/       # Integration tests
│   │   ├── api/           # API integration tests
│   │   └── repositories/  # Database integration tests
│   ├── benchmarks/        # Performance benchmarks
│   │   ├── api/           # API handler benchmarks
│   │   └── repositories/  # Repository benchmarks
│   ├── test_config.go     # Test configuration
│   ├── test_utils.go      # Test utilities
│   └── README.md          # Test documentation
├── scripts/               # Build and utility scripts
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

## 🔄 Migration Summary

### Files Moved

#### Public API (`pkg/`)
- `goauth.go` → `pkg/auth/auth.go`
- `build.config.go` → `pkg/auth/builder.go`
- `config/*` → `pkg/config/*`
- `models/*` → `pkg/types/*`

#### Private Implementation (`internal/`)
- `api/*` → `internal/api/*`
- `database/*` → `internal/database/*`
- `repositories/*` → `internal/repositories/*`
- `notifications/*` → `internal/notifications/*`
- `tokens/*` → `internal/tokens/*`
- `ratelimiter/*` → `internal/ratelimiter/*`
- `recaptcha/*` → `internal/recaptcha/*`
- `hooks/*` → `internal/hooks/*`
- `logger/*` → `internal/logger/*`
- `utils/*` → `internal/utils/*`
- `interfaces/*` → `internal/interfaces/*`
- `schemas/*` → `internal/schemas/*`
- `caches/*` → `internal/caches/*`
- `external/*` → `internal/external/*`

#### Tests (Reorganized)
- `*_test.go` → `tests/unit/*` (by component)
- `integration_test.go` → `tests/integration/*`
- `test_config.go` → `tests/test_config.go`
- Test files moved from internal packages to `tests/unit/` structure:
  - `internal/api/handlers/*_test.go` → `tests/unit/api/handlers/`
  - `internal/repositories/postgres/factory_test.go` → `tests/unit/repositories/postgres/`
  - `internal/hooks/hooks_test.go` → `tests/unit/hooks/`
  - `internal/api/handlers/test_utils.go` → `tests/unit/api/handlers/`

#### Examples
- Created `examples/` directory with framework-specific examples

## 📦 Package Changes

### Public API (`pkg/`)

#### `pkg/auth/`
- **auth.go**: Main public interface for the library
- **builder.go**: Builder pattern for configuration
- **types.go**: Public types and interfaces

#### `pkg/config/`
- All configuration types and constants
- Validation functions
- Default configurations

#### `pkg/types/`
- Public data models
- Common types used across the library

### Private Implementation (`internal/`)

All internal packages are now properly encapsulated and not importable by users.

### Test Organization (`tests/`)

#### `tests/unit/`
- **api/handlers/**: API handler unit tests
- **repositories/**: Repository unit tests
- **hooks/**: Hook system tests
- **tokens/**: Token manager tests

#### `tests/integration/`
- **api/**: API integration tests
- **repositories/**: Database integration tests

#### `tests/benchmarks/`
- **api/**: API handler benchmarks
- **repositories/**: Repository benchmarks

## 🔧 Import Path Updates

### Before
```go
import (
    "github.com/bete7512/goauth/api"
    "github.com/bete7512/goauth/config"
    "github.com/bete7512/goauth/database"
    // ... etc
)
```

### After
```go
import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)
```

## 🎯 Benefits

### 1. **Clear Public API**
- Users only import from `pkg/`
- Internal implementation is hidden
- Better API stability

### 2. **Better Organization**
- Logical separation of concerns
- Easier to find and maintain code
- Follows Go project conventions

### 3. **Improved Maintainability**
- Clear boundaries between public and private code
- Easier refactoring of internal implementation
- Better test organization

### 4. **Enhanced Examples**
- Framework-specific examples
- Better documentation
- Easier onboarding for users

### 5. **Organized Testing**
- Tests separated by type (unit, integration, benchmarks)
- Tests organized by component
- Centralized test configuration and utilities
- No test files scattered in internal packages

## 🚀 Usage Changes

### Before
```go
import "github.com/bete7512/goauth"

auth, err := goauth.NewAuth(config)
```

### After
```go
import "github.com/bete7512/goauth/pkg/auth"

auth, err := auth.NewBuilder().WithConfig(config).Build()
```

## 📋 Migration Checklist

- [x] Create new directory structure
- [x] Move files to appropriate locations
- [x] Update import paths across all files
- [x] Update package names where needed
- [x] Create examples directory
- [x] Add basic examples
- [x] Create framework examples
- [x] Update documentation
- [x] Test build process
- [x] Reorganize test files
- [x] Create test directory structure
- [x] Move test files from internal packages
- [x] Create test configuration and utilities
- [x] Add comprehensive test examples
- [x] Create test documentation

## 🔍 Testing

To verify the restructuring:

```bash
# Test the build
go build ./pkg/auth
go build ./pkg/config
go build ./pkg/types

# Run tests
go test ./tests/unit/...
go test ./tests/integration/...
go test -bench=. ./tests/benchmarks/...

# Test examples
cd examples/basic && go run main.go
cd examples/frameworks/gin && go run main.go
```

## 📚 Documentation Updates

- [x] Updated README.md with new structure
- [x] Created examples documentation
- [x] Added migration guide
- [x] Updated import examples
- [x] Created comprehensive test documentation
- [x] Added test organization guide

## 🎉 Next Steps

1. **Update Documentation**: Ensure all docs reflect new structure
2. **Add More Examples**: Create additional framework examples
3. **Performance Testing**: Verify no performance regressions
4. **User Migration Guide**: Help existing users migrate
5. **Release Notes**: Document breaking changes
6. **Test Implementation**: Implement actual test logic in placeholder tests

## ⚠️ Breaking Changes

This restructuring introduces breaking changes:

1. **Import Paths**: All import paths have changed
2. **Package Names**: Some package names have been updated
3. **API Changes**: Builder pattern is now the primary way to create instances
4. **Test Organization**: Test files are now in dedicated `tests/` directory

Users will need to update their imports and usage patterns.

## 📞 Support

For questions about the restructuring:
- Check the updated documentation
- Review the examples
- Check the test documentation
- Open an issue on GitHub 