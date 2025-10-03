package events

import (
	"context"

	"github.com/bete7512/goauth/pkg/config"
)

// ConfigEvent represents event structure from config package
type ConfigEvent struct {
	Type    string
	Data    interface{}
	Context context.Context
	User    interface{}
	Error   error
}

// EventBusAdapter adapts EventBus to work with config.EventBus interface
type EventBusAdapter struct {
	bus *EventBus
}

// NewEventBusAdapter creates a new event bus adapter
func NewEventBusAdapter(bus *EventBus) *EventBusAdapter {
	return &EventBusAdapter{bus: bus}
}

// Subscribe registers a handler for an event type (string version)
func (a *EventBusAdapter) Subscribe(eventType string, handler config.EventHandler, opts ...interface{}) {
	// Convert string event type to EventType
	et := EventType(eventType)

	// Convert handler signature
	h := func(ctx context.Context, event *Event) error {
		configEvent := &ConfigEvent{
			Type:    string(event.Type),
			Data:    event.Data,
			Context: event.Context,
			User:    event.User,
			Error:   event.Error,
		}
		return handler(ctx, configEvent)
	}

	// Convert opts to SubscribeOptions
	var subscribeOpts []SubscribeOption
	for _, opt := range opts {
		if so, ok := opt.(SubscribeOption); ok {
			subscribeOpts = append(subscribeOpts, so)
		}
	}

	a.bus.Subscribe(et, h, subscribeOpts...)
}

// Emit dispatches an event (string version)
func (a *EventBusAdapter) Emit(ctx context.Context, eventType string, data interface{}) error {
	return a.bus.Emit(ctx, EventType(eventType), data)
}

// EmitSync dispatches an event synchronously (string version)
func (a *EventBusAdapter) EmitSync(ctx context.Context, eventType string, data interface{}) error {
	return a.bus.EmitSync(ctx, EventType(eventType), data)
}
