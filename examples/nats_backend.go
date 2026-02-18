package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSJetStreamBackend implements types.AsyncBackend using NATS JetStream.
//
// Events are published to JetStream subjects for durable, distributed processing.
// Subject format: <prefix>.<event_type> where colons in event types are
// replaced with dots (e.g., "after:signup" → "goauth.events.after.signup").
//
// JetStream handles:
//   - Durable message storage (events survive process restarts)
//   - Server-side deduplication via Nats-Msg-Id header
//   - At-least-once delivery with consumer acknowledgment
//   - Horizontal scaling with multiple consumer instances
//
// The backend handles both publishing and consuming internally — developers
// only need to register handlers via auth.On() and the backend takes care
// of the rest. No separate consumer implementation required.
type NATSJetStreamBackend struct {
	conn         *nats.Conn
	js           jetstream.JetStream
	stream       jetstream.Stream
	streamName   string
	subjPrefix   string
	consumerName string

	mu         sync.Mutex
	consumeCtx jetstream.ConsumeContext // for stopping the consumer on Close
}

// Compile-time check
var _ types.AsyncBackend = (*NATSJetStreamBackend)(nil)

// NATSConfig holds configuration for the NATS JetStream backend.
type NATSConfig struct {
	// URL is the NATS server URL (e.g., "nats://localhost:4222")
	URL string

	// StreamName is the JetStream stream name (default: "GOAUTH_EVENTS")
	StreamName string

	// SubjectPrefix is the subject prefix for events (default: "goauth.events")
	SubjectPrefix string

	// ConsumerName is the durable consumer name (default: "goauth-worker").
	// Multiple instances with the same name will load-balance messages.
	ConsumerName string

	// MaxAge is the maximum age of messages in the stream (default: 24h)
	MaxAge time.Duration

	// MaxMsgs is the maximum number of messages in the stream (default: 100000)
	MaxMsgs int64

	// Username for NATS authentication (optional)
	Username string

	// Password for NATS authentication (optional)
	Password string

	// Token for NATS token-based authentication (optional)
	Token string

	// NKeyFile path to NKey seed file for NATS NKey authentication (optional)
	NKeyFile string

	// CredentialsFile path to credentials file for NATS JWT authentication (optional)
	CredentialsFile string

	// ConnectOptions allows passing additional nats.Option values for
	// TLS, custom dialers, reconnect behavior, etc.
	ConnectOptions []nats.Option

	// DedupWindow is the JetStream deduplication window (default: 5m).
	// JetStream deduplicates automatically within this window using the
	// Nats-Msg-Id header (set to event.ID).
	DedupWindow time.Duration
}

// EventPayload is the JSON-serializable event structure published to NATS.
type EventPayload struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
}

// NewNATSJetStreamBackend creates a NATS JetStream async backend.
// It connects to NATS, initializes JetStream, and creates/updates the stream.
func NewNATSJetStreamBackend(ctx context.Context, cfg *NATSConfig) (*NATSJetStreamBackend, error) {
	if cfg.URL == "" {
		cfg.URL = nats.DefaultURL
	}
	if cfg.StreamName == "" {
		cfg.StreamName = "GOAUTH_EVENTS"
	}
	if cfg.SubjectPrefix == "" {
		cfg.SubjectPrefix = "goauth.events"
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = "goauth-worker"
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 24 * time.Hour
	}
	if cfg.MaxMsgs == 0 {
		cfg.MaxMsgs = 100_000
	}
	if cfg.DedupWindow == 0 {
		cfg.DedupWindow = 5 * time.Minute
	}

	// Build connect options from config
	opts := append([]nats.Option{}, cfg.ConnectOptions...)
	if cfg.Username != "" {
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}
	if cfg.Token != "" {
		opts = append(opts, nats.Token(cfg.Token))
	}
	if cfg.CredentialsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.CredentialsFile))
	}
	if cfg.NKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(cfg.NKeyFile)
		if err != nil {
			return nil, fmt.Errorf("nats nkey: %w", err)
		}
		opts = append(opts, opt)
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     cfg.StreamName,
		Subjects: []string{cfg.SubjectPrefix + ".>"},
		MaxAge:   cfg.MaxAge,
		MaxMsgs:  cfg.MaxMsgs,
		// LimitsPolicy allows multiple independent consumers to each
		// process all events (fan-out). Use WorkQueuePolicy if you want
		// competing consumers where each message is processed once.
		Retention:  jetstream.LimitsPolicy,
		Discard:    jetstream.DiscardOld,
		Duplicates: cfg.DedupWindow,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create stream: %w", err)
	}

	return &NATSJetStreamBackend{
		conn:         nc,
		js:           js,
		stream:       stream,
		streamName:   cfg.StreamName,
		subjPrefix:   cfg.SubjectPrefix,
		consumerName: cfg.ConsumerName,
	}, nil
}

// Publish sends an event to JetStream.
// Uses Nats-Msg-Id for server-side deduplication within the configured window.
func (b *NATSJetStreamBackend) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
	subject := b.subjPrefix + "." + string(eventType)

	dataBytes, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}

	payload := EventPayload{
		ID:        event.ID,
		Type:      string(eventType),
		Data:      dataBytes,
		CreatedAt: event.CreatedAt,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event payload: %w", err)
	}

	// Nats-Msg-Id enables server-side deduplication within the Duplicates window
	_, err = b.js.Publish(ctx, subject, body, jetstream.WithMsgID(event.ID))
	if err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}

	return nil
}

// Subscribe creates a durable JetStream consumer and starts consuming events.
// For each message received, it deserializes the event and calls the dispatcher.
// The dispatcher is provided by EventBus and routes the event to all registered handlers.
//
// Called once by EventBus.Start() after all handlers are registered. This ensures
// that durable messages replayed on restart are dispatched to the correct handlers.
func (b *NATSJetStreamBackend) Subscribe(ctx context.Context, dispatcher types.EventDispatcher) error {
	consumer, err := b.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       b.consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: b.subjPrefix + ".>",
		MaxDeliver:    5,
		AckWait:       30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create consumer %q: %w", b.consumerName, err)
	}

	cctx, err := consumer.Consume(func(msg jetstream.Msg) {
		var payload EventPayload
		if err := json.Unmarshal(msg.Data(), &payload); err != nil {
			log.Printf("nats consumer [%s]: unmarshal error: %v", b.consumerName, err)
			_ = msg.Term()
			return
		}

		// Reconstruct *types.Event. Data is json.RawMessage — handlers use
		// types.EventDataAs[T]() which handles JSON unmarshal transparently.
		event := &types.Event{
			ID:        payload.ID,
			Type:      types.EventType(payload.Type),
			Data:      payload.Data,
			Context:   ctx,
			CreatedAt: payload.CreatedAt,
		}

		dispatcher(ctx, event)

		if err := msg.Ack(); err != nil {
			log.Printf("nats consumer [%s]: ack error (event=%s, id=%s): %v",
				b.consumerName, payload.Type, payload.ID, err)
		}
	})
	if err != nil {
		return fmt.Errorf("start consume: %w", err)
	}

	b.mu.Lock()
	b.consumeCtx = cctx
	b.mu.Unlock()

	return nil
}

// Close stops the consumer and closes the NATS connection.
func (b *NATSJetStreamBackend) Close() error {
	b.mu.Lock()
	if b.consumeCtx != nil {
		b.consumeCtx.Stop()
	}
	b.mu.Unlock()

	b.conn.Close()
	return nil
}

// Name returns the backend name for logging.
func (b *NATSJetStreamBackend) Name() string {
	return "nats-jetstream"
}

