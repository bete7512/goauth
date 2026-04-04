package utils

import (
	"testing"
	"testing/fstest"

	"github.com/bete7512/goauth/pkg/types"
)

func TestParseMigrations(t *testing.T) {
	fs := fstest.MapFS{
		"migrations/postgres/000_init_up.sql":        {Data: []byte("CREATE TABLE users (id TEXT);")},
		"migrations/postgres/000_init_down.sql":      {Data: []byte("DROP TABLE users;")},
		"migrations/postgres/001_add_roles_up.sql":   {Data: []byte("ALTER TABLE users ADD COLUMN role TEXT;")},
		"migrations/postgres/001_add_roles_down.sql": {Data: []byte("ALTER TABLE users DROP COLUMN role;")},
		"migrations/mysql/000_init_up.sql":           {Data: []byte("CREATE TABLE users (id VARCHAR(36));")},
		"migrations/mysql/000_init_down.sql":         {Data: []byte("DROP TABLE users;")},
	}

	result := ParseMigrations(fs)

	// Check postgres
	pg, ok := result[types.DialectTypePostgres]
	if !ok {
		t.Fatal("expected postgres migrations")
	}
	if len(pg) != 2 {
		t.Fatalf("expected 2 postgres migrations, got %d", len(pg))
	}
	if pg[0].Version != 0 || pg[0].Name != "init" {
		t.Errorf("pg[0]: got version=%d name=%q, want version=0 name=init", pg[0].Version, pg[0].Name)
	}
	if pg[1].Version != 1 || pg[1].Name != "add_roles" {
		t.Errorf("pg[1]: got version=%d name=%q, want version=1 name=add_roles", pg[1].Version, pg[1].Name)
	}
	if string(pg[0].Up) != "CREATE TABLE users (id TEXT);" {
		t.Errorf("pg[0].Up = %q", string(pg[0].Up))
	}

	// Check mysql
	my, ok := result[types.DialectTypeMysql]
	if !ok {
		t.Fatal("expected mysql migrations")
	}
	if len(my) != 1 {
		t.Fatalf("expected 1 mysql migration, got %d", len(my))
	}

	// Check sqlite (none provided)
	if _, ok := result[types.DialectTypeSqlite]; ok {
		t.Error("expected no sqlite migrations")
	}
}

func TestParseMigrationFilename(t *testing.T) {
	tests := []struct {
		fname     string
		version   int
		name      string
		direction string
		wantErr   bool
	}{
		{"000_init_up.sql", 0, "init", "up", false},
		{"000_init_down.sql", 0, "init", "down", false},
		{"001_add_roles_up.sql", 1, "add_roles", "up", false},
		{"012_fix_index_down.sql", 12, "fix_index", "down", false},
		{"bad.sql", 0, "", "", true},
		{"no_version_up.sql", 0, "", "", true},
	}

	for _, tt := range tests {
		v, n, d, err := parseMigrationFilename(tt.fname)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: expected error", tt.fname)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tt.fname, err)
			continue
		}
		if v != tt.version || n != tt.name || d != tt.direction {
			t.Errorf("%s: got (%d, %q, %q), want (%d, %q, %q)", tt.fname, v, n, d, tt.version, tt.name, tt.direction)
		}
	}
}
