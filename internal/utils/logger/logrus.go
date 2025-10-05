package logger

import (
	"github.com/sirupsen/logrus"
)

// LogrusLogger is a logger adapter for logrus
type LogrusLogger struct {
	logger *logrus.Entry
}

// NewLogrusLogger creates a new logrus-based logger with default configuration
func NewLogrusLogger() *LogrusLogger {
	log := logrus.New()

	// Set default formatter (JSON)
	log.SetFormatter(&logrus.JSONFormatter{})

	// Set default log level
	log.SetLevel(logrus.InfoLevel)

	return &LogrusLogger{
		logger: logrus.NewEntry(log),
	}
}

// NewLogrusLoggerWithConfig creates a new logrus-based logger with custom configuration
func NewLogrusLoggerWithConfig(log *logrus.Logger) *LogrusLogger {
	return &LogrusLogger{
		logger: logrus.NewEntry(log),
	}
}

// NewLogrusLoggerFromEntry creates a logger from an existing logrus entry
func NewLogrusLoggerFromEntry(entry *logrus.Entry) *LogrusLogger {
	return &LogrusLogger{
		logger: entry,
	}
}

func (l *LogrusLogger) Info(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.WithFields(argsToFields(args...)).Info(msg)
	} else {
		l.logger.Info(msg)
	}
}

func (l *LogrusLogger) Error(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.WithFields(argsToFields(args...)).Error(msg)
	} else {
		l.logger.Error(msg)
	}
}

func (l *LogrusLogger) Debug(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.WithFields(argsToFields(args...)).Debug(msg)
	} else {
		l.logger.Debug(msg)
	}
}

func (l *LogrusLogger) Warn(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.WithFields(argsToFields(args...)).Warn(msg)
	} else {
		l.logger.Warn(msg)
	}
}

func (l *LogrusLogger) Trace(msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.WithFields(argsToFields(args...)).Trace(msg)
	} else {
		l.logger.Trace(msg)
	}
}

func (l *LogrusLogger) Infof(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

func (l *LogrusLogger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}

func (l *LogrusLogger) Debugf(format string, args ...interface{}) {
	l.logger.Debugf(format, args...)
}

func (l *LogrusLogger) Warnf(format string, args ...interface{}) {
	l.logger.Warnf(format, args...)
}

func (l *LogrusLogger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatalf(format, args...)
}

func (l *LogrusLogger) WithFields(fields map[string]interface{}) Logger {
	return &LogrusLogger{
		logger: l.logger.WithFields(logrus.Fields(fields)),
	}
}

// argsToFields converts variadic args to logrus Fields
// Expects args to be in key-value pairs: key1, value1, key2, value2, ...
func argsToFields(args ...interface{}) logrus.Fields {
	fields := make(logrus.Fields)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, ok := args[i].(string)
			if ok {
				fields[key] = args[i+1]
			}
		}
	}
	return fields
}
