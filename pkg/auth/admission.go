package auth

import (
	"context"
	"fmt"
	"net/http"
)

func (a *Auth) acquire(ctx context.Context, operation string) (func(), error) {
	select {
	case a.requestSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("authentication capacity exceeded")
	}
	release := func() { <-a.requestSlots }
	if a.config.Admission != nil {
		external, err := a.config.Admission.Acquire(ctx, operation)
		if err != nil {
			release()
			return nil, err
		}
		return func() {
			if external != nil {
				external()
			}
			release()
		}, nil
	}
	return release, nil
}

type observedResponse struct {
	http.ResponseWriter
	status int
}

func (w *observedResponse) WriteHeader(status int) {
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Unwrap supports http.ResponseController for flushing/hijacking host responses.
func (w *observedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
