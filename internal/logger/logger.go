package logger

import (
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	logger Log       // package-level global logger instance
	once   sync.Once // ensure New only runs once
)

type LogOptions struct {
	DisableAll     bool
	DisableInfo    bool
	DisableDebug   bool
	DisableWarning bool
}
type Log interface {
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	SetFormatter(formatter logrus.Formatter)
	SetReportCaller(reportCaller bool)
}

type loggerImpl struct {
	log     *logrus.Logger
	options LogOptions
}

type noOpLogger struct{}

func (n *noOpLogger) Debug(args ...interface{})                 {}
func (n *noOpLogger) Debugf(format string, args ...interface{}) {}
func (n *noOpLogger) Info(args ...interface{})                  {}
func (n *noOpLogger) Infof(format string, args ...interface{})  {}
func (n *noOpLogger) Warn(args ...interface{})                  {}
func (n *noOpLogger) Warnf(format string, args ...interface{})  {}
func (n *noOpLogger) Error(args ...interface{})                 {}
func (n *noOpLogger) Errorf(format string, args ...interface{}) {}
func (n *noOpLogger) Fatal(args ...interface{})                 {}
func (n *noOpLogger) Fatalf(format string, args ...interface{}) {}
func (n *noOpLogger) SetFormatter(formatter logrus.Formatter)   {}
func (n *noOpLogger) SetReportCaller(reportCaller bool)         {}

func New(level string, opts LogOptions) {
	once.Do(func() {
		if opts.DisableAll {
			logger = &noOpLogger{}
			return
		}
		l := logrus.New()
		l.SetOutput(os.Stdout)
		l.SetFormatter(&logrus.JSONFormatter{})
		switch level {
		case "debug":
			l.SetLevel(logrus.DebugLevel)
		case "info":
			l.SetLevel(logrus.InfoLevel)
		case "warn":
			l.SetLevel(logrus.WarnLevel)
		case "error":
			l.SetLevel(logrus.ErrorLevel)
		default:
			l.Warnf("Unknown log level: %s. Defaulting to info.", level)
			l.SetLevel(logrus.InfoLevel)
		}
		logger = &loggerImpl{log: l, options: opts}
	})
}

func Get() Log {
	if logger == nil {
		New("info", LogOptions{
			DisableAll:     false,
			DisableInfo:    false,
			DisableDebug:   false,
			DisableWarning: false,
		})
	}
	return logger
}

// fallback logger if New() wasn't called yet
func getLogger() Log {
	if logger == nil {
		New("info", LogOptions{
			DisableAll:     false,
			DisableInfo:    false,
			DisableDebug:   false,
			DisableWarning: false,
		})
	}
	return logger
}

// Now expose package-level functions that call logger methods:

func Debug(args ...interface{}) {
	getLogger().Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	getLogger().Debugf(format, args...)
}

func Info(args ...interface{}) {
	getLogger().Info(args...)
}

func Infof(format string, args ...interface{}) {
	getLogger().Infof(format, args...)
}

func Warn(args ...interface{}) {
	getLogger().Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	getLogger().Warnf(format, args...)
}

func Error(args ...interface{}) {
	getLogger().Error(args...)
}

func Errorf(format string, args ...interface{}) {
	getLogger().Errorf(format, args...)
}

func Fatal(args ...interface{}) {
	getLogger().Fatal(args...)
}

func Fatalf(format string, args ...interface{}) {
	getLogger().Fatalf(format, args...)
}

// Implement Log interface for loggerImpl

func (l *loggerImpl) Debug(args ...interface{}) {
	if l.options.DisableDebug || l.options.DisableAll {
		return
	}
	l.log.Debug(args...)
}

func (l *loggerImpl) Debugf(format string, args ...interface{}) {
	if l.options.DisableDebug || l.options.DisableAll {
		return
	}
	l.log.Debugf(format, args...)
}

func (l *loggerImpl) Info(args ...interface{}) {
	if l.options.DisableInfo || l.options.DisableAll {
		return
	}
	l.log.Info(args...)
}

func (l *loggerImpl) Infof(format string, args ...interface{}) {
	if l.options.DisableInfo || l.options.DisableAll {
		return
	}
	l.log.Infof(format, args...)
}

func (l *loggerImpl) Warn(args ...interface{}) {
	if l.options.DisableWarning || l.options.DisableAll {
		return
	}
	l.log.Warn(args...)
}

func (l *loggerImpl) Warnf(format string, args ...interface{}) {
	if l.options.DisableWarning || l.options.DisableAll {
		return
	}
	l.log.Warnf(format, args...)
}

func (l *loggerImpl) Error(args ...interface{}) {
	l.log.Error(args...)
}

func (l *loggerImpl) Errorf(format string, args ...interface{}) {
	l.log.Errorf(format, args...)
}

func (l *loggerImpl) Fatal(args ...interface{}) {
	l.log.Fatal(args...)
}

func (l *loggerImpl) Fatalf(format string, args ...interface{}) {
	l.log.Fatalf(format, args...)
}

func (l *loggerImpl) SetFormatter(formatter logrus.Formatter) {
	l.log.SetFormatter(formatter)
}

func (l *loggerImpl) SetReportCaller(reportCaller bool) {
	l.log.SetReportCaller(reportCaller)
}
