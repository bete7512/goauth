package interceptor

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/bete7512/goauth/pkg/types"
)

// Compile-time check
var _ types.AuthInterceptorRegistry = (*Registry)(nil)

type entry struct {
	name        string
	interceptor types.AuthInterceptor
	priority    int
}

// Registry is the concrete implementation of AuthInterceptorRegistry.
// Interceptors are sorted by priority descending (higher priority runs first).
type Registry struct {
	mu      sync.RWMutex
	entries []entry
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(name string, interceptor types.AuthInterceptor, priority int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = append(r.entries, entry{
		name:        name,
		interceptor: interceptor,
		priority:    priority,
	})

	// Sort descending by priority (higher priority runs first)
	sort.Slice(r.entries, func(i, j int) bool {
		return r.entries[i].priority > r.entries[j].priority
	})
}

func (r *Registry) Run(ctx context.Context, params *types.InterceptParams) (map[string]interface{}, []types.LoginChallenge, error) {
	r.mu.RLock()
	entries := make([]entry, len(r.entries))
	copy(entries, r.entries)
	r.mu.RUnlock()

	mergedClaims := make(map[string]interface{})
	var challenges []types.LoginChallenge

	for _, e := range entries {
		result, err := e.interceptor(ctx, params)
		if err != nil {
			return nil, nil, fmt.Errorf("interceptor %q failed: %w", e.name, err)
		}
		if result == nil {
			continue
		}

		// Merge claims (later interceptors override earlier ones for same key)
		for k, v := range result.Claims {
			mergedClaims[k] = v
		}

		// Only collect challenges during login phase
		if params.Phase == types.PhaseLogin && result.Challenge != nil {
			challenges = append(challenges, *result.Challenge)
		}
	}

	return mergedClaims, challenges, nil
}
