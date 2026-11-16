package models

import (
	"context"
	"time"
)

// DailyCount is how many rows fall on one UTC day, given as "2006-01-02".
type DailyCount struct {
	Day   string
	Count int64
}

// UserSignupCounter is implemented by user stores that can count new users
// per day. It is optional: the admin console shows its sign-up chart only
// when the store provides it.
type UserSignupCounter interface {
	CountCreatedPerDay(ctx context.Context, since time.Time) ([]DailyCount, error)
}

// AuditActionCounter is implemented by audit stores that can count events
// of one action per day, for the admin console's activity charts.
type AuditActionCounter interface {
	CountActionPerDay(ctx context.Context, action string, since time.Time) ([]DailyCount, error)
}
