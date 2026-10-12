package interceptor

import (
	"context"
	"fmt"
	"github.com/bete7512/goauth/internal/security"
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
		if r.entries[i].priority == r.entries[j].priority {
			return r.entries[i].name < r.entries[j].name
		}
		return r.entries[i].priority > r.entries[j].priority
	})
}

func (r *Registry) Run(ctx context.Context, params *types.InterceptParams) (map[string]interface{}, []types.LoginChallenge, map[string]interface{}, error) {
	r.mu.RLock()
	entries := make([]entry, len(r.entries))
	copy(entries, r.entries)
	r.mu.RUnlock()

	mergedClaims := make(map[string]interface{})
	responseData := make(map[string]interface{})
	var challenges []types.LoginChallenge

	for _, e := range entries {
		result, err := e.interceptor(ctx, params)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("interceptor %q failed: %w", e.name, err)
		}
		if result == nil {
			continue
		}

		// Merge claims (later interceptors override earlier ones for same key)
		for k, v := range result.Claims {
			if security.IsReservedClaim(k) {
				return nil, nil, nil, fmt.Errorf("interceptor %q attempted reserved claim %q", e.name, k)
			}
			if _, exists := mergedClaims[k]; exists {
				return nil, nil, nil, fmt.Errorf("duplicate interceptor claim %q", k)
			}
			mergedClaims[k] = v
		}

		// Merge response data (module-specific data for response body, NOT JWT)
		for k, v := range result.ResponseData {
			responseData[k] = v
		}

		// Only collect challenges during login phase
		if result.Challenge != nil {
			challenges = append(challenges, *result.Challenge)
		}
	}

	return mergedClaims, challenges, responseData, nil
}
