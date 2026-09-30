package daemon

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

const tagAnchorHost = "anchor.invalid"

// The anchor is sealed for a different host, so every read drops it as a domain-hash
// mismatch and only the write path sees its v10 tag.
func plantStoreTagAnchor(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(linuxMetaSchema); err != nil {
		t.Fatalf("meta: %v", err)
	}
	_, err := db.Exec(
		`INSERT INTO cookies VALUES (1, ?, '', 'anchor', '', ?, '/', 0, 0, 0, 1, 0, 0, 1, 0, 2, 443, 1, 0, 0)`,
		tagAnchorHost, sealLinuxV10(t, "other."+tagAnchorHost, "anchor"),
	)
	if err != nil {
		t.Fatalf("plant tag anchor: %v", err)
	}
}

func withoutTagAnchor(rows []cookie.EncryptedRow) []cookie.EncryptedRow {
	return slices.DeleteFunc(slices.Clone(rows), func(row cookie.EncryptedRow) bool { return row.HostKey == tagAnchorHost })
}
