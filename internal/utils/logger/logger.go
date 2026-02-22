package logger

import "github.com/bete7512/goauth/pkg/types"

//go:generate mockgen -destination=../../mocks/mock_logger.go -package=mocks github.com/bete7512/goauth/internal/utils/logger Logger

// Logger is a type alias for types.Logger.
// All internal code continues to work unchanged; the interface is now defined in pkg/types
// so external module authors can reference it without importing internal packages.
type Logger = types.Logger
