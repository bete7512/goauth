package types

import (
	"context"
	"time"
)

// AdmissionController can enforce a shared budget across replicas. Keys are
// operation names, never credentials or unconstrained user input.
type AdmissionController interface {
	Acquire(context.Context, string) (release func(), err error)
}

// OperationObserver is called after each built-in route with the route name,
// its duration and whether the response status was below 400.
type OperationObserver interface {
	ObserveOperation(context.Context, string, time.Duration, bool)
}
