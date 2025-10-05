package logger

// Logger is the unified interface for logging across the entire application.
// Users can implement this interface to provide their own logger
// (e.g., logrus, zap, zerolog, or any custom implementation).
type Logger interface {
	// Structured logging with key-value pairs
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Trace(msg string, args ...interface{})

	// Printf-style logging
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})

	// WithFields returns a logger with pre-set fields
	WithFields(fields map[string]interface{}) Logger
}
