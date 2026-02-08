//go:build integration

package integration_test

import (
	"testing"
)

// Integration tests require a running database.
// Run with: go test -tags=integration ./tests/integration/
//
// Set the following environment variables:
//   GOAUTH_TEST_DSN - database connection string

func TestPlaceholder(t *testing.T) {
	t.Skip("placeholder: add real integration tests with database fixtures")
}
