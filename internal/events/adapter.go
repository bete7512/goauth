package events

import (
	"context"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// // ConfigEvent represents event structure from config package
// type ConfigEvent struct {
// 	Type    string
// 	Data    interface{}
// 	Context context.Context
// 	Error   error
// }

// EventBusAdapter adapts EventBus to work with config.EventBus interface
type EventBusAdapter struct {
	bus *EventBus
}

// NewEventBusAdapter creates a new event bus adapter
func NewEventBusAdapter(bus *EventBus) *EventBusAdapter {
	return &EventBusAdapter{bus: bus}
}

// Subscribe registers a handler for an event type (string version)
func (a *EventBusAdapter) Subscribe(eventType types.EventType, handler config.EventHandler, opts ...interface{}) {
	// Convert string event type to EventType
	et := types.EventType(eventType)

	// Convert handler signature
	h := func(ctx context.Context, event *types.Event) error {
		configEvent := &types.Event{
			Type:    event.Type,
			Data:    event.Data,
			Context: event.Context,
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
func (a *EventBusAdapter) Emit(ctx context.Context, eventType types.EventType, data interface{}) error {
	return a.bus.Emit(ctx, eventType, data)
}

// EmitSync dispatches an event synchronously (string version)
func (a *EventBusAdapter) EmitSync(ctx context.Context, eventType types.EventType, data interface{}) error {
	return a.bus.EmitSync(ctx, eventType, data)
}
