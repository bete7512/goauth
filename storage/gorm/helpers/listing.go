package helpers

import (
	"fmt"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// ApplyListingOpts applies pagination and sorting to a GORM query.
// SortField must already be validated against an allowlist before calling this.
func ApplyListingOpts(db *gorm.DB, opts models.ListingOpts) *gorm.DB {
	orderClause := fmt.Sprintf("%s %s", opts.SortField, opts.SortDir)
	return db.Order(orderClause).Limit(opts.Limit).Offset(opts.Offset)
}
