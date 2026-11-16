package helpers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// safeIdentifier rejects anything that isn't a simple column name (letters, digits, underscores).
var safeIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ApplyListingOpts applies pagination and sorting to a GORM query.
// Enforces safe defaults: SortField must be a valid SQL identifier,
// SortDir must be "asc" or "desc". Invalid values are replaced with
// safe defaults to prevent SQL injection even if the caller forgot to
// call Normalize() on the opts.
func ApplyListingOpts(db *gorm.DB, opts models.ListingOpts) *gorm.DB {
	sortField := opts.SortField
	if sortField == "" || !safeIdentifier.MatchString(sortField) {
		sortField = "created_at"
	}
	sortDir := opts.SortDir
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}
	orderClause := fmt.Sprintf("%s %s", sortField, sortDir)
	return db.Order(orderClause).Limit(opts.Limit).Offset(opts.Offset)
}

// ContainsPattern returns a LIKE pattern that matches value anywhere, in
// lower case, with LIKE wildcards in value escaped by '!'. Use it as
// "LOWER(column) LIKE ? ESCAPE '!'", which every supported dialect accepts.
func ContainsPattern(value string) string {
	escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(value))
	return "%" + escaped + "%"
}
