package types

import (
	"net/http"
	"testing"
	"time"
)

func TestNewConfigurationErrorUsesTheGivenMessage(t *testing.T) {
	msg := "jwt secret key must be at least 32 characters"
	if got := NewConfigurationError(&msg).Message; got != msg {
		t.Fatalf("message = %q, want %q", got, msg)
	}
	if got := NewConfigurationError(nil).Message; got != "Configuration error" {
		t.Fatalf("default message = %q", got)
	}
}

func TestNewRateLimitExceededErrorRoundsRetryUp(t *testing.T) {
	err := NewRateLimitExceededError(1500 * time.Millisecond)
	if err.StatusCode != http.StatusTooManyRequests || err.Code != ErrRateLimitExceeded {
		t.Fatalf("unexpected error %+v", err)
	}
	if got := err.Details.(map[string]any)["retry_after_seconds"]; got != int64(2) {
		t.Fatalf("retry_after_seconds = %v, want 2", got)
	}
	if got := NewRateLimitExceededError(0).Details.(map[string]any)["retry_after_seconds"]; got != int64(1) {
		t.Fatalf("minimum retry = %v, want 1", got)
	}
}
