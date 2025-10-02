package auth

import (
	"context"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/events"
)

// simpleEventBusAdapter adapts events.EventBus to config.EventBus
type simpleEventBusAdapter struct {
	bus *events.EventBus
}

func (a *simpleEventBusAdapter) Subscribe(eventType string, handler config.EventHandler, opts ...interface{}) {
	// Convert config.EventHandler to events.Handler
	eventsHandler := func(ctx context.Context, event *events.Event) error {
		return handler(ctx, event.Data)
	}

	// Convert opts to events.SubscribeOption
	var subscribeOpts []events.SubscribeOption
	for _, opt := range opts {
		if so, ok := opt.(events.SubscribeOption); ok {
			subscribeOpts = append(subscribeOpts, so)
		}
	}

	a.bus.Subscribe(events.EventType(eventType), eventsHandler, subscribeOpts...)
}

func (a *simpleEventBusAdapter) Emit(ctx context.Context, eventType string, data interface{}) error {
	return a.bus.Emit(ctx, events.EventType(eventType), data)
}

func (a *simpleEventBusAdapter) EmitSync(ctx context.Context, eventType string, data interface{}) error {
	return a.bus.EmitSync(ctx, events.EventType(eventType), data)
}

// loggerAdapter adapts config.Logger to events.Logger
type loggerAdapter struct {
	logger config.Logger
}

func (l *loggerAdapter) Info(msg string, args ...interface{}) {
	l.logger.Info(msg, args...)
}

// simpleLoggerAdapter adapts events.Logger to config.Logger
type simpleLoggerAdapter struct {
	logger events.Logger
}

func (l *simpleLoggerAdapter) Info(msg string, args ...interface{}) {
	l.logger.Info(msg, args...)
}

func (l *simpleLoggerAdapter) Error(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
}

func (l *simpleLoggerAdapter) Debug(msg string, args ...interface{}) {
	l.logger.Debug(msg, args...)
}

func (l *simpleLoggerAdapter) Warn(msg string, args ...interface{}) {
	l.logger.Warn(msg, args...)
}
