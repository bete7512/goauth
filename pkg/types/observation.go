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

type OperationObserver interface {
	ObserveOperation(context.Context, string, time.Duration, bool)
}
