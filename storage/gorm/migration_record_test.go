package gorm

import (
	"strings"
	"sync"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm/schema"
)

// MySQL cannot index TEXT columns without a key length, and GORM's MySQL driver
// maps unsized strings to longtext. Every indexed string column of the
// migrations tracking table must therefore carry an explicit size.
func TestMigrationRecordIndexedColumnsHaveLengthOnMySQL(t *testing.T) {
	parsed, err := schema.Parse(&gormMigrationRecord{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	dialector := mysql.Dialector{Config: &mysql.Config{}}
	for _, name := range []string{"ID", "ModuleName"} {
		field := parsed.LookUpField(name)
		if field == nil {
			t.Fatalf("field %s not found", name)
		}
		if typ := dialector.DataTypeOf(field); !strings.HasPrefix(typ, "varchar(") {
			t.Fatalf("%s maps to %q on MySQL; indexed columns need a length", name, typ)
		}
	}
}
