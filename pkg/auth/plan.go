package auth

import (
	"fmt"
	"github.com/bete7512/goauth/pkg/config"
	"sort"
	"strings"
)

// modulePlan validates the complete graph, independent of registration order.
func (a *Auth) modulePlan() ([]string, error) {
	names := make([]string, 0, len(a.modules))
	for name := range a.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	providers := map[string]string{}
	constraints := map[string]config.ModuleConstraints{}
	for _, name := range names {
		if m, ok := a.modules[name].(config.ConstrainedModule); ok {
			c := m.Constraints()
			constraints[name] = c
			for _, capability := range c.Provides {
				if other, exists := providers[capability]; exists {
					return nil, fmt.Errorf("capability %q has multiple providers: %s, %s", capability, other, name)
				}
				providers[capability] = name
			}
		}
	}
	edges := map[string][]string{}
	for _, name := range names {
		c := constraints[name]
		for _, conflict := range c.Conflicts {
			if _, exists := a.modules[conflict]; exists {
				return nil, fmt.Errorf("module %s conflicts with %s", name, conflict)
			}
		}
		deps := append([]string(nil), a.modules[name].Dependencies()...)
		for _, capability := range c.Requires {
			provider, exists := providers[capability]
			if !exists {
				return nil, fmt.Errorf("module %s requires missing capability %q", name, capability)
			}
			if provider != name {
				deps = append(deps, provider)
			}
		}
		sort.Strings(deps)
		for _, dep := range deps {
			if _, exists := a.modules[dep]; !exists {
				return nil, fmt.Errorf("module %s requires missing dependency %s", name, dep)
			}
		}
		edges[name] = deps
	}
	state := map[string]int{}
	var order, stack []string
	var visit func(string) error
	visit = func(name string) error {
		if state[name] == 2 {
			return nil
		}
		if state[name] == 1 {
			return fmt.Errorf("module dependency cycle: %s", strings.Join(append(stack, name), " -> "))
		}
		state[name] = 1
		stack = append(stack, name)
		for _, dep := range edges[name] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		stack = stack[:len(stack)-1]
		state[name] = 2
		order = append(order, name)
		return nil
	}
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return order, nil
}
