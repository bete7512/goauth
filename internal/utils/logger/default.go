package logger

import (
	"fmt"
	"time"
)

// DefaultLogger is a simple console logger implementation.
// It prints logs to stdout with timestamps.
type DefaultLogger struct {
	fields map[string]interface{}
}

// NewDefaultLogger creates a new default console logger
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		fields: make(map[string]interface{}),
	}
}

func (l *DefaultLogger) log(level, msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Format the message
	formatted := fmt.Sprintf("%s [%s] %s", timestamp, level, msg)

	// Add fields if present
	if len(l.fields) > 0 {
		formatted += " fields="
		formatted += fmt.Sprintf("%v", l.fields)
	}

	// Add additional args if present
	if len(args) > 0 {
		formatted += " "
		formatted += fmt.Sprint(args...)
	}

	fmt.Println(formatted)
}

func (l *DefaultLogger) Info(msg string, args ...interface{}) {
	l.log("INFO", msg, args...)
}

func (l *DefaultLogger) Error(msg string, args ...interface{}) {
	l.log("ERROR", msg, args...)
}

func (l *DefaultLogger) Debug(msg string, args ...interface{}) {
	l.log("DEBUG", msg, args...)
}

func (l *DefaultLogger) Warn(msg string, args ...interface{}) {
	l.log("WARN", msg, args...)
}

func (l *DefaultLogger) Trace(msg string, args ...interface{}) {
	l.log("TRACE", msg, args...)
}

func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	l.log("INFO", fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	l.log("ERROR", fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	l.log("DEBUG", fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) Warnf(format string, args ...interface{}) {
	l.log("WARN", fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) Fatalf(format string, args ...interface{}) {
	l.log("FATAL", fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) WithFields(fields map[string]interface{}) Logger {
	// Create a new logger with combined fields
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &DefaultLogger{
		fields: newFields,
	}
}
