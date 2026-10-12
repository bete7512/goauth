package auth

import "fmt"

func (a *Auth) validateRoutes() error {
	if err := a.middlewareManager.ValidateRequirements(nil); err != nil {
		return err
	}
	names, endpoints := map[string]bool{}, map[string]string{}
	for _, route := range a.routes {
		if route.Name == "" || route.Method == "" || route.Path == "" || route.Handler == nil {
			return fmt.Errorf("invalid route %q", route.Name)
		}
		if names[route.Name] {
			return fmt.Errorf("duplicate route name %q", route.Name)
		}
		names[route.Name] = true
		key := route.Method + " " + route.Path
		if other, exists := endpoints[key]; exists {
			return fmt.Errorf("route collision %s: %s and %s", key, other, route.Name)
		}
		endpoints[key] = route.Name
		if err := a.middlewareManager.ValidateRequirements(route.Middlewares); err != nil {
			return fmt.Errorf("route %s: %w", route.Name, err)
		}
	}
	return nil
}
