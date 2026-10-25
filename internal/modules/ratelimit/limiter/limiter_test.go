package limiter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

func TestDecideBurstThenRefill(t *testing.T) {
	rule := types.RateLimitRule{Limit: 5, Window: 10 * time.Second}
	now := time.Unix(1_700_000_000, 0)
	var tat int64
	for i := 0; i < 5; i++ {
		var decision types.RateLimitDecision
		tat, decision = Decide(tat, now, rule)
		if !decision.Allowed {
			t.Fatalf("request %d denied", i+1)
		}
		if decision.Remaining != 4-i {
			t.Fatalf("remaining after request %d = %d, want %d", i+1, decision.Remaining, 4-i)
		}
		if decision.Limit != 5 {
			t.Fatalf("limit = %d, want 5", decision.Limit)
		}
	}
	denied, decision := Decide(tat, now, rule)
	if decision.Allowed {
		t.Fatal("sixth request allowed")
	}
	if denied != tat {
		t.Fatal("denied request changed stored state")
	}
	if decision.RetryAfter != 2*time.Second {
		t.Fatalf("retry after = %v, want 2s", decision.RetryAfter)
	}
	if decision.Remaining != 0 {
		t.Fatalf("remaining on denial = %d, want 0", decision.Remaining)
	}

	// One token is back after one emission interval.
	_, decision = Decide(tat, now.Add(2*time.Second), rule)
	if !decision.Allowed || decision.Remaining != 0 {
		t.Fatalf("after 2s: allowed=%v remaining=%d", decision.Allowed, decision.Remaining)
	}
	// The full budget is back after the window.
	_, decision = Decide(tat, now.Add(10*time.Second), rule)
	if !decision.Allowed || decision.Remaining != 4 {
		t.Fatalf("after window: allowed=%v remaining=%d", decision.Allowed, decision.Remaining)
	}
}

func TestDecideBurstSmallerThanLimit(t *testing.T) {
	rule := types.RateLimitRule{Limit: 60, Window: time.Minute, Burst: 5}
	now := time.Unix(1_700_000_000, 0)
	var tat int64
	for i := 0; i < 5; i++ {
		var decision types.RateLimitDecision
		tat, decision = Decide(tat, now, rule)
		if !decision.Allowed {
			t.Fatalf("burst request %d denied", i+1)
		}
	}
	_, decision := Decide(tat, now, rule)
	if decision.Allowed {
		t.Fatal("request beyond burst allowed")
	}
	if decision.RetryAfter != time.Second {
		t.Fatalf("retry after = %v, want 1s", decision.RetryAfter)
	}
	if decision.Limit != 5 {
		t.Fatalf("advertised limit = %d, want burst 5", decision.Limit)
	}
}

func TestDecideZeroRuleNeverLimits(t *testing.T) {
	now := time.Now()
	for _, rule := range []types.RateLimitRule{{}, {Limit: 0, Window: time.Second}, {Limit: 5}} {
		if _, decision := Decide(0, now, rule); !decision.Allowed {
			t.Fatalf("rule %+v limited", rule)
		}
	}
}

func TestMemoryStoreAllowsExactlyLimitUnderConcurrency(t *testing.T) {
	store := NewMemoryStore(0)
	rule := types.RateLimitRule{Limit: 100, Window: time.Minute}
	now := time.Now()
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, err := store.Take(context.Background(), "rl:test:ip:203.0.113.1", rule, now)
			if err != nil {
				t.Error(err)
				return
			}
			if decision.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 100 {
		t.Fatalf("allowed %d requests, want exactly 100", allowed.Load())
	}
}

func TestMemoryStoreKeysAreIndependent(t *testing.T) {
	store := NewMemoryStore(0)
	rule := types.RateLimitRule{Limit: 1, Window: time.Minute}
	now := time.Now()
	if d, _ := store.Take(context.Background(), "a", rule, now); !d.Allowed {
		t.Fatal("first request for key a denied")
	}
	if d, _ := store.Take(context.Background(), "a", rule, now); d.Allowed {
		t.Fatal("second request for key a allowed")
	}
	if d, _ := store.Take(context.Background(), "b", rule, now); !d.Allowed {
		t.Fatal("first request for key b denied")
	}
}

func TestMemoryStoreResetRestoresBudget(t *testing.T) {
	store := NewMemoryStore(0)
	rule := types.RateLimitRule{Limit: 1, Window: time.Hour}
	now := time.Now()
	_, _ = store.Take(context.Background(), "k", rule, now)
	if d, _ := store.Take(context.Background(), "k", rule, now); d.Allowed {
		t.Fatal("expected denial before reset")
	}
	if err := store.Reset(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if d, _ := store.Take(context.Background(), "k", rule, now); !d.Allowed {
		t.Fatal("expected allowance after reset")
	}
}

func TestMemoryStoreBoundsTrackedKeys(t *testing.T) {
	store := NewMemoryStore(64) // one key per shard
	rule := types.RateLimitRule{Limit: 10, Window: time.Hour}
	now := time.Now()
	for i := 0; i < 5000; i++ {
		if _, err := store.Take(context.Background(), fmt.Sprintf("rl:test:ip:10.0.%d.%d", i/256, i%256), rule, now); err != nil {
			t.Fatal(err)
		}
	}
	if n := store.Len(); n > 64 {
		t.Fatalf("tracked %d keys, cap is 64", n)
	}
}

func TestMemoryStoreSweepDropsExpiredEntries(t *testing.T) {
	store := NewMemoryStore(0)
	rule := types.RateLimitRule{Limit: 1, Window: time.Second}
	start := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = store.Take(context.Background(), fmt.Sprintf("old-%d", i), rule, start)
	}
	if n := store.Len(); n != 100 {
		t.Fatalf("tracking %d keys before sweep, want 100", n)
	}
	// Touching every shard after the sweep interval drops the expired entries.
	later := start.Add(2 * time.Minute)
	const probes = 2000
	for i := 0; i < probes; i++ {
		_, _ = store.Take(context.Background(), fmt.Sprintf("probe-%d", i), rule, later)
	}
	if n := store.Len(); n != probes {
		t.Fatalf("tracking %d keys after sweep, want only the %d live probes", n, probes)
	}
}
