package gorm

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMigrationQuotedStatements(t *testing.T) {
	script := `-- comment; not a statement
CREATE TABLE "semi;colon" (value TEXT);
INSERT INTO "semi;colon" VALUES ('a; b''; c'); /* nested /* ; */ comment; */
DO $body$ BEGIN PERFORM 'a;b'; END; $body$;
-- trailing comment;
`
	statements, err := splitSQLStatements(script)
	require.NoError(t, err)
	require.Len(t, statements, 3)
	require.Contains(t, statements[1], "'a; b''; c'")
	require.Contains(t, statements[2], "BEGIN PERFORM 'a;b'; END;")
	for _, sql := range []string{"SELECT 'unterminated", "/* unfinished", "DO $body$ unfinished"} {
		_, err := splitSQLStatements(sql)
		require.Error(t, err)
	}
}
