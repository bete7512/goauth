package types

// Logger is the unified interface for structured logging.
// Implement this interface to plug in any logger (logrus, zap, zerolog, etc.)
// and supply it via config.Config.Logger. If nil, a logrus default is used.
type Logger interface {
	// Structured logging — args are key-value pairs: Info("msg", "key", val)
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Trace(msg string, args ...interface{})

	// Printf-style logging
	Infof(format string, args ...interface{})
	Tracef(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})

	// WithFields returns a child logger with pre-set fields.
	WithFields(fields map[string]interface{}) Logger
}
