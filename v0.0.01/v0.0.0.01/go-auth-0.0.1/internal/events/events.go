package events

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// EventType represents different event types in the authentication flow
type EventType string

const (
	// User events
	EventBeforeSignup EventType = "before:signup"
	EventAfterSignup  EventType = "after:signup"
	EventBeforeLogin  EventType = "before:login"
	EventAfterLogin   EventType = "after:login"
	EventBeforeLogout EventType = "before:logout"
	EventAfterLogout  EventType = "after:logout"

	// Session events
	EventSessionCreated EventType = "session:created"
	EventSessionExpired EventType = "session:expired"
	EventSessionRevoked EventType = "session:revoked"

	// Password events
	EventPasswordChanged      EventType = "password:changed"
	EventPasswordResetRequest EventType = "password:reset:request"
	EventPasswordReset        EventType = "password:reset"

	// Two-factor events
	EventTwoFactorEnabled  EventType = "2fa:enabled"
	EventTwoFactorDisabled EventType = "2fa:disabled"
	EventTwoFactorVerified EventType = "2fa:verified"

	// Email events
	EventEmailVerificationSent EventType = "email:verification:sent"
	EventEmailVerified         EventType = "email:verified"
)

// Event represents an event with associated data
type Event struct {
	Type    EventType
	Data    interface{}
	Context context.Context
	User    interface{}
	Error   error
}

// Handler is a function that handles an event
type Handler func(ctx context.Context, event *Event) error

// handlerWithPriority wraps a handler with priority
type handlerWithPriority struct {
	handler  Handler
	priority int
	async    bool
}

// EventBus manages event handlers and dispatches events
type EventBus struct {
	handlers     map[EventType][]handlerWithPriority
	mu           sync.RWMutex
	logger       Logger
	asyncBackend AsyncBackend // Pluggable async backend
}

// Logger interface for event bus logging
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
}

// NewEventBus creates a new event bus with default worker pool backend
func NewEventBus(logger Logger) *EventBus {
	return NewEventBusWithBackend(logger, nil)
}

// NewEventBusWithBackend creates an event bus with custom async backend
// If backend is nil, uses default worker pool (workers=10, queueSize=1000)
func NewEventBusWithBackend(logger Logger, backend AsyncBackend) *EventBus {
	if backend == nil {
		// Use default worker pool backend
		backend = NewDefaultAsyncBackend(10, 1000, logger)
	}

	if logger != nil {
		logger.Info("EventBus initialized with async backend", "backend", backend.Name())
	}

	return &EventBus{
		handlers:     make(map[EventType][]handlerWithPriority),
		logger:       logger,
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
func (eb *EventBus) Subscribe(eventType EventType, handler Handler, opts ...SubscribeOption) {
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
func (eb *EventBus) Emit(ctx context.Context, eventType EventType, data interface{}) error {
	eb.mu.RLock()
	handlers := eb.handlers[eventType]
	eb.mu.RUnlock()

	if len(handlers) == 0 {
		return nil
	}

	event := &Event{
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
func (eb *EventBus) EmitSync(ctx context.Context, eventType EventType, data interface{}) error {
	eb.mu.RLock()
	handlers := eb.handlers[eventType]
	eb.mu.RUnlock()

	if len(handlers) == 0 {
		return nil
	}

	event := &Event{
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
func (eb *EventBus) Unsubscribe(eventType EventType) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	delete(eb.handlers, eventType)
}

// HasHandlers checks if there are handlers for an event type
func (eb *EventBus) HasHandlers(eventType EventType) bool {
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

// DefaultLogger is a simple logger implementation
type DefaultLogger struct{}

func (l *DefaultLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] %s %v\n", msg, args)
}

func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *DefaultLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] %s %v\n", msg, args)
}

func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

func (l *DefaultLogger) Debug(msg string, args ...interface{}) {
	fmt.Printf("[DEBUG] %s %v\n", msg, args)
}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

func (l *DefaultLogger) Warn(msg string, args ...interface{}) {
	fmt.Printf("[WARN] %s %v\n", msg, args)
}

func (l *DefaultLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *DefaultLogger) Trace(msg string, args ...interface{}) {
	fmt.Printf("[TRACE] %s %v\n", msg, args)
}

func (l *DefaultLogger) Fatalf(format string, args ...interface{}) {
	fmt.Printf("[FATAL] "+format+"\n", args...)
}
