// Package limiter implements the rate-limit engine (GCRA, a token bucket
// expressed as a single timestamp per key) and the built-in memory store.
package limiter

import (
	"context"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

// Decide charges one request against rule. tat is the stored theoretical
// arrival time for the key in Unix nanoseconds (zero when unknown). It returns
// the value to store when the request is allowed and the decision.
//
// With emission interval T = Window/Limit and tolerance τ = T*Burst, a request
// is allowed when tat' - τ <= now where tat' = max(tat, now) + T. The first
// Burst requests pass immediately; the budget then refills at Limit per
// Window. A rule with a non-positive Limit or Window never limits.
func Decide(tat int64, now time.Time, rule types.RateLimitRule) (int64, types.RateLimitDecision) {
	if rule.Limit <= 0 || rule.Window <= 0 {
		return tat, types.RateLimitDecision{Allowed: true, Limit: rule.Limit, Remaining: rule.Limit, ResetAt: now}
	}
	burst := rule.Burst
	if burst <= 0 {
		burst = rule.Limit
	}
	interval := int64(rule.Window) / int64(rule.Limit)
	if interval <= 0 {
		interval = 1
	}
	tolerance := interval * int64(burst)
	nowNanos := now.UnixNano()
	base := tat
	if base < nowNanos {
		base = nowNanos
	}
	next := base + interval
	allowAt := next - tolerance
	if allowAt > nowNanos {
		return tat, types.RateLimitDecision{
			Allowed:    false,
			Limit:      burst,
			Remaining:  0,
			RetryAfter: time.Duration(allowAt - nowNanos),
			ResetAt:    time.Unix(0, base),
		}
	}
	remaining := int((tolerance - (next - nowNanos)) / interval)
	if remaining < 0 {
		remaining = 0
	}
	return next, types.RateLimitDecision{
		Allowed:   true,
		Limit:     burst,
		Remaining: remaining,
		ResetAt:   time.Unix(0, next),
	}
}

const (
	shardCount    = 64
	sweepInterval = int64(time.Minute)
)

// MemoryStore is a process-local RateLimitStore. It keeps one int64 per key in
// sharded maps, sweeps a shard's expired entries at most once a minute while
// serving requests, and evicts arbitrary entries when a shard exceeds its share of
// MaxKeys so memory stays bounded under key-spraying attacks. It starts no
// goroutines.
type MemoryStore struct {
	shards      [shardCount]shard
	perShardCap int
}

type shard struct {
	mu        sync.Mutex
	lastSweep int64
	tats      map[string]int64
}

// DefaultMaxKeys bounds the memory store when no cap is configured.
const DefaultMaxKeys = 100_000

// NewMemoryStore returns a memory store tracking at most maxKeys keys
// (DefaultMaxKeys when maxKeys <= 0).
func NewMemoryStore(maxKeys int) *MemoryStore {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	perShard := maxKeys / shardCount
	if perShard < 1 {
		perShard = 1
	}
	s := &MemoryStore{perShardCap: perShard}
	for i := range s.shards {
		s.shards[i].tats = make(map[string]int64)
	}
	return s
}

var _ types.RateLimitStore = (*MemoryStore)(nil)

// Take implements types.RateLimitStore.
func (s *MemoryStore) Take(_ context.Context, key string, rule types.RateLimitRule, now time.Time) (types.RateLimitDecision, error) {
	sh := &s.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	nowNanos := now.UnixNano()
	if nowNanos-sh.lastSweep >= sweepInterval {
		sh.sweep(nowNanos)
		sh.lastSweep = nowNanos
	}
	tat, exists := sh.tats[key]
	next, decision := Decide(tat, now, rule)
	if !decision.Allowed {
		return decision, nil
	}
	if !exists && len(sh.tats) >= s.perShardCap {
		sh.sweep(nowNanos)
		if len(sh.tats) >= s.perShardCap {
			sh.evict(s.perShardCap/8 + 1)
		}
	}
	sh.tats[key] = next
	return decision, nil
}

// Reset implements types.RateLimitStore.
func (s *MemoryStore) Reset(_ context.Context, key string) error {
	sh := &s.shards[shardIndex(key)]
	sh.mu.Lock()
	delete(sh.tats, key)
	sh.mu.Unlock()
	return nil
}

// Close implements types.RateLimitStore. It drops all tracked keys.
func (s *MemoryStore) Close() error {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		sh.tats = make(map[string]int64)
		sh.mu.Unlock()
	}
	return nil
}

// Len returns the number of tracked keys.
func (s *MemoryStore) Len() int {
	total := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		total += len(sh.tats)
		sh.mu.Unlock()
	}
	return total
}

// sweep drops entries whose budget is fully replenished; they are equivalent
// to absent keys. Caller holds the shard lock.
func (sh *shard) sweep(nowNanos int64) {
	for key, tat := range sh.tats {
		if tat <= nowNanos {
			delete(sh.tats, key)
		}
	}
}

// evict removes up to n arbitrary entries. Caller holds the shard lock.
func (sh *shard) evict(n int) {
	for key := range sh.tats {
		if n <= 0 {
			return
		}
		delete(sh.tats, key)
		n--
	}
}

// shardIndex is FNV-1a over key, inlined to avoid allocating a hasher.
func shardIndex(key string) int {
	const offset32, prime32 = 2166136261, 16777619
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return int(h % shardCount)
}
