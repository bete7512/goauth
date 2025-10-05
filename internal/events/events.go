package events

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

// Event represents an event with associated data

// Handler is a function that handles an event

// handlerWithPriority wraps a handler with priority
type handlerWithPriority struct {
	handler  types.EventHandler
	priority int
	async    bool
}

// EventBus manages event handlers and dispatches events
type EventBus struct {
	handlers     map[types.EventType][]handlerWithPriority
	mu           sync.RWMutex
	logger       logger.Logger
	asyncBackend types.AsyncBackend // Pluggable async backend
}

// NewEventBus creates a new event bus with default worker pool backend
func NewEventBus(log logger.Logger) *EventBus {
	return NewEventBusWithBackend(log, nil)
}

// NewEventBusWithBackend creates an event bus with custom async backend
// If backend is nil, uses default worker pool (workers=10, queueSize=1000)
func NewEventBusWithBackend(log logger.Logger, backend types.AsyncBackend) *EventBus {
	if backend == nil {
		// Use default worker pool backend
		backend = NewDefaultAsyncBackend(10, 1000, log)
	}

	if log != nil {
		log.Info("EventBus initialized with async backend", "backend", backend.Name())
	}

	return &EventBus{
		handlers:     make(map[types.EventType][]handlerWithPriority),
		logger:       log,
		asyncBackend: backend,
	}
}

// Close gracefully shuts down the event bus
func (eb *EventBus) Close() error {
	if eb.asyncBackend != nil {
		return eb.asyncBackend.Close()
	}
	return nil
}

// Subscribe registers a handler for an event type
func (eb *EventBus) Subscribe(eventType types.EventType, handler types.EventHandler, opts ...SubscribeOption) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	h := handlerWithPriority{
		handler:  handler,
		priority: 0,
		async:    false,
	}

	for _, opt := range opts {
		opt(&h)
	}

	eb.handlers[eventType] = append(eb.handlers[eventType], h)

	// Sort handlers by priority (higher priority first)
	sort.Slice(eb.handlers[eventType], func(i, j int) bool {
		return eb.handlers[eventType][i].priority > eb.handlers[eventType][j].priority
	})
}

// Emit dispatches an event to all registered handlers
// Sync handlers execute immediately, async handlers use the backend
func (eb *EventBus) Emit(ctx context.Context, eventType types.EventType, data interface{}) error {
	eb.mu.RLock()
	handlers := eb.handlers[eventType]
	eb.mu.RUnlock()

	if len(handlers) == 0 {
		return nil
	}

	event := &types.Event{
		Type:    eventType,
		Data:    data,
		Context: ctx,
	}

	// Execute sync handlers first
	for _, h := range handlers {
		if !h.async {
			if err := h.handler(ctx, event); err != nil {
				return fmt.Errorf("handler error for %s: %w", eventType, err)
			}
		}
	}

	// Submit async handlers to backend
	for _, h := range handlers {
		if h.async {
			// Use custom backend if it's not the default
			if defaultBackend, ok := eb.asyncBackend.(*DefaultAsyncBackend); ok {
				// Use worker pool
				if err := defaultBackend.SubmitJob(ctx, h.handler, event); err != nil {
					if eb.logger != nil {
						eb.logger.Error("Failed to submit async job", "event", eventType, "error", err)
					}
				}
			} else {
				// Use external queue (Redis, RabbitMQ, etc.)
				// The handler will be executed by external consumers
				if err := eb.asyncBackend.Publish(ctx, eventType, event); err != nil {
					if eb.logger != nil {
						eb.logger.Error("Failed to publish to async backend", "event", eventType, "error", err)
					}
				}
			}
		}
	}

	return nil
}

// EmitSync dispatches an event synchronously to all handlers
func (eb *EventBus) EmitSync(ctx context.Context, eventType types.EventType, data interface{}) error {
	eb.mu.RLock()
	handlers := eb.handlers[eventType]
	eb.mu.RUnlock()

	if len(handlers) == 0 {
		return nil
	}

	event := &types.Event{
		Type:    eventType,
		Data:    data,
		Context: ctx,
	}

	for _, h := range handlers {
		if err := h.handler(ctx, event); err != nil {
			return fmt.Errorf("handler error for %s: %w", eventType, err)
		}
	}

	return nil
}

// Unsubscribe removes all handlers for an event type
func (eb *EventBus) Unsubscribe(eventType types.EventType) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	delete(eb.handlers, eventType)
}

// HasHandlers checks if there are handlers for an event type
func (eb *EventBus) HasHandlers(eventType types.EventType) bool {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.handlers[eventType]) > 0
}

// SubscribeOption configures handler subscription
type SubscribeOption func(*handlerWithPriority)

// WithPriority sets the priority of the handler
// Higher priority handlers are executed first (default: 0)
func WithPriority(priority int) SubscribeOption {
	return func(h *handlerWithPriority) {
		h.priority = priority
	}
}

// WithAsync makes the handler execute asynchronously
func WithAsync() SubscribeOption {
	return func(h *handlerWithPriority) {
		h.async = true
	}
}
