package utils

import (
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/bete7512/goauth/pkg/types"
)

// ParseMigrations scans an embed.FS for versioned migration files and returns ModuleMigrations.
//
// Expected file layout inside the FS:
//
//	migrations/{dialect}/{version}_{name}_up.sql
//	migrations/{dialect}/{version}_{name}_down.sql
//
// Example:
//
//	migrations/postgres/000_init_up.sql
//	migrations/postgres/000_init_down.sql
//	migrations/postgres/001_add_roles_up.sql
//	migrations/postgres/001_add_roles_down.sql
func ParseMigrations(fsys fs.FS) types.ModuleMigrations {
	result := types.ModuleMigrations{}

	for _, dialect := range []types.DialectType{types.DialectTypePostgres, types.DialectTypeMysql, types.DialectTypeSqlite} {
		dir := "migrations/" + string(dialect)
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			continue
		}

		// Collect up/down files keyed by version
		type migPair struct {
			version int
			name    string
			up      []byte
			down    []byte
		}
		pairs := map[int]*migPair{}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fname := entry.Name()
			if !strings.HasSuffix(fname, ".sql") {
				continue
			}

			version, name, direction, err := parseMigrationFilename(fname)
			if err != nil {
				continue
			}

			p, ok := pairs[version]
			if !ok {
				p = &migPair{version: version, name: name}
				pairs[version] = p
			}

			data, err := fs.ReadFile(fsys, dir+"/"+fname)
			if err != nil {
				continue
			}

			switch direction {
			case "up":
				p.up = data
			case "down":
				p.down = data
			}
		}

		// Sort by version and build the slice
		versions := make([]int, 0, len(pairs))
		for v := range pairs {
			versions = append(versions, v)
		}
		sort.Ints(versions)

		migrations := make([]types.VersionedMigration, 0, len(versions))
		for _, v := range versions {
			p := pairs[v]
			if len(p.up) == 0 {
				continue // skip migrations without an up file
			}
			migrations = append(migrations, types.VersionedMigration{
				Version: p.version,
				Name:    p.name,
				Up:      p.up,
				Down:    p.down,
			})
		}

		if len(migrations) > 0 {
			result[dialect] = migrations
		}
	}

	return result
}

// parseMigrationFilename parses "000_init_up.sql" into (0, "init", "up", nil).
func parseMigrationFilename(fname string) (version int, name string, direction string, err error) {
	// Strip .sql suffix
	base := strings.TrimSuffix(fname, ".sql")

	// Must end with _up or _down
	if strings.HasSuffix(base, "_up") {
		direction = "up"
		base = strings.TrimSuffix(base, "_up")
	} else if strings.HasSuffix(base, "_down") {
		direction = "down"
		base = strings.TrimSuffix(base, "_down")
	} else {
		return 0, "", "", fmt.Errorf("filename %q does not end with _up or _down", fname)
	}

	// Split into version and name: "000_init" → ["000", "init"]
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 {
		return 0, "", "", fmt.Errorf("filename %q missing version_name prefix", fname)
	}

	version, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", "", fmt.Errorf("filename %q has non-numeric version: %w", fname, err)
	}
	name = parts[1]

	return version, name, direction, nil
}
