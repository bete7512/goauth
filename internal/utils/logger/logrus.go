package logger

import (
	"fmt"
	"runtime"

	"github.com/sirupsen/logrus"
)

type LogrusLogger struct {
	logger *logrus.Entry
}


func captureCaller(skip int) logrus.Fields {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}

	return logrus.Fields{
		"caller": fmt.Sprintf("%s:%d", file, line), // absolute path
	}
}

// NewLogrusLogger creates a new logrus-based logger with default configuration
func NewLogrusLogger() *LogrusLogger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	return &LogrusLogger{
		logger: logrus.NewEntry(log),
	}
}

func NewLogrusLoggerWithConfig(log *logrus.Logger) *LogrusLogger {
	return &LogrusLogger{logger: logrus.NewEntry(log)}
}

func NewLogrusLoggerFromEntry(entry *logrus.Entry) *LogrusLogger {
	return &LogrusLogger{logger: entry}
}

// ---------- Logging Methods ----------

func (l *LogrusLogger) Info(msg string, args ...interface{}) {
	fields := captureCaller(2) // <-- skip two frames (this + Info caller)
	if len(args) > 0 {
		for k, v := range argsToFields(args...) {
			fields[k] = v
		}
	}
	l.logger.WithFields(fields).Info(msg)
}

func (l *LogrusLogger) Error(msg string, args ...interface{}) {
	fields := captureCaller(2)
	if len(args) > 0 {
		for k, v := range argsToFields(args...) {
			fields[k] = v
		}
	}
	l.logger.WithFields(fields).Error(msg)
}

func (l *LogrusLogger) Debug(msg string, args ...interface{}) {
	fields := captureCaller(2)
	if len(args) > 0 {
		for k, v := range argsToFields(args...) {
			fields[k] = v
		}
	}
	l.logger.WithFields(fields).Debug(msg)
}

func (l *LogrusLogger) Warn(msg string, args ...interface{}) {
	fields := captureCaller(2)
	if len(args) > 0 {
		for k, v := range argsToFields(args...) {
			fields[k] = v
		}
	}
	l.logger.WithFields(fields).Warn(msg)
}

func (l *LogrusLogger) Trace(msg string, args ...interface{}) {
	fields := captureCaller(2)
	if len(args) > 0 {
		for k, v := range argsToFields(args...) {
			fields[k] = v
		}
	}
	l.logger.WithFields(fields).Trace(msg)
}

// ---------- Printf-style methods ----------

func (l *LogrusLogger) Infof(format string, args ...interface{}) {
	l.logger.WithFields(captureCaller(2)).Infof(format, args...)
}

func (l *LogrusLogger) Errorf(format string, args ...interface{}) {
	l.logger.WithFields(captureCaller(2)).Errorf(format, args...)
}

func (l *LogrusLogger) Debugf(format string, args ...interface{}) {
	l.logger.WithFields(captureCaller(2)).Debugf(format, args...)
}

func (l *LogrusLogger) Warnf(format string, args ...interface{}) {
	l.logger.WithFields(captureCaller(2)).Warnf(format, args...)
}

func (l *LogrusLogger) Fatalf(format string, args ...interface{}) {
	l.logger.WithFields(captureCaller(2)).Fatalf(format, args...)
}

// ---------- Structured ----------

func (l *LogrusLogger) WithFields(fields map[string]interface{}) Logger {
	return &LogrusLogger{
		logger: l.logger.WithFields(logrus.Fields(fields)),
	}
}

func argsToFields(args ...interface{}) logrus.Fields {
	fields := make(logrus.Fields)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			if key, ok := args[i].(string); ok {
				fields[key] = args[i+1]
			}
		}
	}
	return fields
}
