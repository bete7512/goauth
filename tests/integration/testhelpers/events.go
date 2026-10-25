//go:build integration

package testhelpers

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

// EventRecorder records events emitted by an initialized Auth instance.
// Single-use secrets are stored as digests, so tests read the raw link or code
// from the delivery event, the way a notification sender would receive it.
type EventRecorder struct {
	mu     sync.Mutex
	events []*types.Event
}

// RecordEvents subscribes to eventTypes on an initialized Auth instance.
func RecordEvents(a *auth.Auth, eventTypes ...types.EventType) *EventRecorder {
	r := &EventRecorder{}
	for _, eventType := range eventTypes {
		a.On(eventType, func(_ context.Context, event *types.Event) error {
			r.mu.Lock()
			r.events = append(r.events, event)
			r.mu.Unlock()
			return nil
		})
	}
	return r
}

// Nth waits for the n-th (1-based) recorded payload of type T that satisfies
// match. Delivery is asynchronous; it gives up after two seconds.
func Nth[T any](t *testing.T, r *EventRecorder, n int, match func(T) bool) T {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		seen := 0
		for _, event := range r.events {
			if data, ok := types.EventDataAs[T](event); ok && match(data) {
				seen++
				if seen == n {
					r.mu.Unlock()
					return data
				}
			}
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			var zero T
			t.Fatalf("event %d of %T was not delivered (saw %d)", n, zero, seen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// InvitationToken returns the token from the link in the platform invitation
// event for invitationID. The setup must configure the invitation CallbackURL.
func InvitationToken(t *testing.T, r *EventRecorder, invitationID string) string {
	t.Helper()
	data := Nth(t, r, 1, func(d *types.InvitationEventData) bool { return d.InvitationID == invitationID })
	return tokenFromLink(t, data.InviteLink)
}

// OrgInvitationToken returns the token from the link in the newest
// organization invitation event sent to email.
func OrgInvitationToken(t *testing.T, r *EventRecorder, email string) string {
	t.Helper()
	data := Nth(t, r, 1, func(d *types.OrgInvitationEventData) bool { return d.Email == email })
	return tokenFromLink(t, data.InviteLink)
}

func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	token := parsed.Query().Get("token")
	require.NotEmpty(t, token, "link %q carries no token", link)
	return token
}
