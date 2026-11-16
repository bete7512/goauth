package services

import (
	"context"
	"sync"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
)

// A memo remembers what a user holds for the rest of one request, so that a
// route guard and the service behind it do not both hit the database. It
// lives in the request context and nowhere else: nothing is cached between
// requests, which is why a revoked role stops working on the next one.
type memo struct {
	mu       sync.Mutex
	holdings map[memoKey]*Holding
}

type memoKey struct {
	userID string
	scope  access.Scope
}

type memoContextKey struct{}

// WithMemo returns a context in which holdings are remembered. Calling it on
// a context that already has a memo keeps the existing one.
func WithMemo(ctx context.Context) context.Context {
	if _, ok := ctx.Value(memoContextKey{}).(*memo); ok {
		return ctx
	}
	return context.WithValue(ctx, memoContextKey{}, &memo{holdings: map[memoKey]*Holding{}})
}

// ResetMemo forgets what was remembered. Every write to roles or assignments
// calls it, so a check made later in the same request sees the change.
func ResetMemo(ctx context.Context) {
	if m, ok := ctx.Value(memoContextKey{}).(*memo); ok {
		m.mu.Lock()
		m.holdings = map[memoKey]*Holding{}
		m.mu.Unlock()
	}
}

func memoGet(ctx context.Context, userID string, scope access.Scope) (*Holding, bool) {
	m, ok := ctx.Value(memoContextKey{}).(*memo)
	if !ok {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	holding, found := m.holdings[keyFor(userID, scope)]
	return holding, found
}

func memoPut(ctx context.Context, holding *Holding) {
	m, ok := ctx.Value(memoContextKey{}).(*memo)
	if !ok {
		return
	}
	m.mu.Lock()
	m.holdings[keyFor(holding.UserID, holding.Scope)] = holding
	m.mu.Unlock()
}

// keyFor names a holding by user and scope. A team scope's organization is
// filled in on the way, so it is not part of the key.
func keyFor(userID string, scope access.Scope) memoKey {
	return memoKey{userID: userID, scope: access.Scope{Type: scope.Type, ID: scope.ID}}
}
