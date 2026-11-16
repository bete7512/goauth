package helpers

import (
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

// DayExpression returns SQL that formats column as its UTC day,
// "2006-01-02", in the database's dialect.
func DayExpression(db *gorm.DB, column string) string {
	if !safeIdentifier.MatchString(column) {
		column = "created_at"
	}
	switch db.Name() {
	case "postgres":
		return fmt.Sprintf("TO_CHAR(%s AT TIME ZONE 'UTC', 'YYYY-MM-DD')", column)
	case "mysql":
		return fmt.Sprintf("DATE_FORMAT(%s, '%%Y-%%m-%%d')", column)
	default:
		return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s)", column)
	}
}

// CountPerDay counts the rows of query per UTC day of created_at from since
// on, oldest first.
func CountPerDay(query *gorm.DB, since time.Time) ([]models.DailyCount, error) {
	day := DayExpression(query, "created_at")
	var rows []models.DailyCount
	err := query.Where("created_at >= ?", since.UTC()).
		Select(day + " AS day, COUNT(*) AS count").
		Group(day).Order("day asc").Scan(&rows).Error
	return rows, err
}
