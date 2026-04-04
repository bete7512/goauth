package models

import "errors"

// ErrNotFound is returned by repository methods when the requested record does not exist.
// Callers should use errors.Is(err, models.ErrNotFound) to check for this condition.
var ErrNotFound = errors.New("record not found")
