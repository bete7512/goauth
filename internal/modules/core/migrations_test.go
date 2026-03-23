package core

import (
	"testing"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/types"
)

func TestCoreMigrationsEmbedded(t *testing.T) {
	result := utils.ParseMigrations(migrationFS)

	for _, dialect := range []types.DialectType{types.DialectTypePostgres, types.DialectTypeMysql, types.DialectTypeSqlite} {
		migrations, ok := result[dialect]
		if !ok {
			t.Errorf("missing migrations for dialect %s", dialect)
			continue
		}
		if len(migrations) == 0 {
			t.Errorf("empty migrations for dialect %s", dialect)
			continue
		}
		m := migrations[0]
		if m.Version != 0 {
			t.Errorf("dialect %s: expected version 0, got %d", dialect, m.Version)
		}
		if m.Name != "init" {
			t.Errorf("dialect %s: expected name 'init', got %q", dialect, m.Name)
		}
		if len(m.Up) == 0 {
			t.Errorf("dialect %s: empty up migration", dialect)
		}
		if len(m.Down) == 0 {
			t.Errorf("dialect %s: empty down migration", dialect)
		}
		t.Logf("dialect %s: version=%d name=%s up=%d bytes down=%d bytes", dialect, m.Version, m.Name, len(m.Up), len(m.Down))
	}
}
