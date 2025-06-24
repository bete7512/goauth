package config

import "time"

type LimiterConfig struct {
	WindowSize    time.Duration
	MaxRequests   int
	BlockDuration time.Duration
}
