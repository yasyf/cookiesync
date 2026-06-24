package cookie

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite" // registers the "sqlite" database/sql driver
	sqlite3 "modernc.org/sqlite/lib"
)

// Schema-version-aware I/O against Chrome's SQLite cookie store.
//
// Reads copy the live Cookies DB (plus its -wal/-shm/-journal sidecars) into a
// private temp dir and open the copy, so a running browser is never disturbed and
// the WAL checkpoints into the copy before we SELECT. Writes go to the live DB,
// best-effort: a short busy_timeout plus a soft-busy -1 return on a locked DB,
// never a forced clobber.
//
// Chrome's cookie schema drifts across versions: v18 carries is_same_party and a
// UNIQUE(host_key, top_frame_site_key, name, path) index, while v24 drops
// is_same_party, adds source_type + has_cross_site_ancestor, and widens the unique
// index to include has_cross_site_ancestor, source_scheme, and source_port. Every
// operation introspects the actual table and unique index via PRAGMA table_info /
// PRAGMA index_list / PRAGMA index_info rather than hardcoding one column set.

const (
	driverName    = "sqlite"
	busyTimeoutMS = 250
)

var sidecarSuffixes = [...]string{"-wal", "-shm", "-journal"}

// rowFieldDefaults zero-fills the columns absent from older schemas, so a v18 row
// (no last_update_utc, no has_cross_site_ancestor) still builds a full EncryptedRow.
var rowFieldDefaults = map[string]any{
	"encrypted_value":         []byte(nil),
	"value":                   "",
	"source_scheme":           int64(2),
	"source_port":             int64(443),
	"top_frame_site_key":      "",
	"has_cross_site_ancestor": int64(0),
	"last_update_utc":         int64(0),
}

// upsertUpdateColumns are the columns refreshed on a unique-index conflict; the
// rest of the row (creation, path, source_*) is left as first inserted.
var upsertUpdateColumns = [...]string{
	"encrypted_value", "value", "expires_utc", "last_update_utc", "is_secure", "is_httponly", "samesite",
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case nil:
		return 0
	default:
		return 0
	}
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	case nil:
		return ""
	default:
		return ""
	}
}

func asBytes(v any) []byte {
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	case nil:
		return nil
	default:
		return nil
	}
}

func isBusy(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	code := serr.Code() & 0xFF
	return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
}

func rowFromColumns(columns []string, values []any) EncryptedRow {
	cells := make(map[string]any, len(rowFieldDefaults)+len(columns))
	for k, v := range rowFieldDefaults {
		cells[k] = v
	}
	for i, c := range columns {
		cells[c] = values[i]
	}
	return EncryptedRow{
		HostKey:              HostKey(asString(cells["host_key"])),
		Name:                 asString(cells["name"]),
		EncryptedValue:       asBytes(cells["encrypted_value"]),
		Value:                asString(cells["value"]),
		Path:                 asString(cells["path"]),
		ExpiresUTC:           ChromeMicros(asInt64(cells["expires_utc"])),
		LastUpdateUTC:        ChromeMicros(asInt64(cells["last_update_utc"])),
		CreationUTC:          ChromeMicros(asInt64(cells["creation_utc"])),
		IsSecure:             asInt64(cells["is_secure"]) != 0,
		IsHTTPOnly:           asInt64(cells["is_httponly"]) != 0,
		SameSite:             int(asInt64(cells["samesite"])),
		SourceScheme:         int(asInt64(cells["source_scheme"])),
		SourcePort:           int(asInt64(cells["source_port"])),
		TopFrameSiteKey:      asString(cells["top_frame_site_key"]),
		HasCrossSiteAncestor: int(asInt64(cells["has_cross_site_ancestor"])),
	}
}

func tableColumns(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(cookies)")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, typ        string
			dflt             any
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func uniqueIndexColumns(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA index_list(cookies)")
	if err != nil {
		return nil, err
	}
	var name string
	found := false
	for rows.Next() {
		var (
			seq, unique, partial int
			idxName, origin      string
		)
		if err := rows.Scan(&seq, &idxName, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if unique == 1 && partial == 0 && !found {
			name, found = idxName, true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("cookies table has no usable unique index")
	}

	info, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA index_info(%q)", name))
	if err != nil {
		return nil, err
	}
	defer func() { _ = info.Close() }()
	var columns []string
	for info.Next() {
		var (
			seqno, cid int
			colName    string
		)
		if err := info.Scan(&seqno, &cid, &colName); err != nil {
			return nil, err
		}
		columns = append(columns, colName)
	}
	return columns, info.Err()
}

// copyFile copies the live cookie store (or one of its sidecars) to a private temp
// dir. Both paths are the tool's own resolved browser layout and temp-dir-derived
// copies, never user-supplied.
func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // G304: src is the tool's own browser cookie DB / sidecar path, not user-supplied.
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst) //nolint:gosec // G304: dst is inside a freshly created private temp dir, not user-supplied.
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copyWithSidecars(db, destDir string) (string, error) {
	copyPath := filepath.Join(destDir, "Cookies")
	if err := copyFile(db, copyPath); err != nil {
		return "", err
	}
	for _, suffix := range sidecarSuffixes {
		side := db + suffix
		if info, err := os.Stat(side); err == nil && !info.IsDir() {
			if err := copyFile(side, copyPath+suffix); err != nil {
				return "", err
			}
		}
	}
	return copyPath, nil
}

// Read returns every cookie row in profile as a raw EncryptedRow, read off a
// private copy of the live store. The Cookies DB and its WAL/journal sidecars are
// copied to a temp dir and the copy is checkpointed before the read, so a row still
// pinned in an uncheckpointed -wal sidecar (the state a running browser leaves on
// disk) is visible. Only columns present in this store's schema are selected;
// absent columns fall back to their defaults.
func Read(ctx context.Context, browser Browser, profile string) ([]EncryptedRow, error) {
	tmpDir, err := os.MkdirTemp("", "cookiesync-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	copyPath, err := copyWithSidecars(browser.CookiesDB(profile), tmpDir)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(driverName, copyPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return nil, fmt.Errorf("wal checkpoint: %w", err)
	}

	columns, err := tableColumns(ctx, db)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM cookies", strings.Join(columns, ", ")))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []EncryptedRow
	for rows.Next() {
		values := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, rowFromColumns(columns, values))
	}
	return out, rows.Err()
}

func insertValues(cookie Cookie, encrypted []byte) map[string]any {
	creation := cookie.CreationUTC
	if creation <= 0 {
		creation = unixToChromeMicros(time.Now())
	}
	hasExpires := int64(0)
	if cookie.ExpiresUTC > 0 {
		hasExpires = 1
	}
	return map[string]any{
		"creation_utc":            int64(creation),
		"host_key":                string(cookie.HostKey),
		"top_frame_site_key":      cookie.TopFrameSiteKey,
		"name":                    cookie.Name,
		"value":                   "",
		"encrypted_value":         encrypted,
		"path":                    cookie.Path,
		"expires_utc":             int64(cookie.ExpiresUTC),
		"is_secure":               boolToInt(cookie.IsSecure),
		"is_httponly":             boolToInt(cookie.IsHTTPOnly),
		"last_access_utc":         int64(cookie.LastUpdateUTC),
		"has_expires":             hasExpires,
		"is_persistent":           hasExpires,
		"priority":                int64(1),
		"samesite":                int64(cookie.SameSite),
		"source_scheme":           int64(cookie.SourceScheme),
		"source_port":             int64(cookie.SourcePort),
		"last_update_utc":         int64(cookie.LastUpdateUTC),
		"source_type":             int64(0),
		"has_cross_site_ancestor": int64(cookie.HasCrossSiteAncestor),
		"is_same_party":           int64(0),
	}
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func upsertSQL(columns, conflict []string) string {
	placeholders := make([]string, len(columns))
	for i, c := range columns {
		placeholders[i] = ":" + c
	}
	conflictSet := make(map[string]struct{}, len(columns))
	for _, c := range columns {
		conflictSet[c] = struct{}{}
	}
	var updates []string
	for _, c := range upsertUpdateColumns {
		if _, ok := conflictSet[c]; ok {
			updates = append(updates, fmt.Sprintf("%s = excluded.%s", c, c))
		}
	}
	return fmt.Sprintf(
		"INSERT INTO cookies (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(conflict, ", "),
		strings.Join(updates, ", "),
	)
}

// Write encrypts and upserts cookies into profile's live Cookies DB and returns
// the number of rows written. Each value is re-encrypted into a v10 blob (the
// plaintext value column is left empty) and written with INSERT ... ON
// CONFLICT(<this store's real unique index>) DO UPDATE, so a re-synced cookie
// collapses onto its existing row. The cookie's own last_update_utc and
// creation_utc are preserved, never stamped to "now". On a locked database this
// returns -1 (soft busy) rather than forcing a write.
func Write(ctx context.Context, browser Browser, profile string, cookies []Cookie, key AesKey) (int, error) {
	db, err := sql.Open(driverName, browser.CookiesDB(profile))
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMS)); err != nil {
		return 0, err
	}

	columns, err := tableColumns(ctx, db)
	if err != nil {
		return 0, err
	}
	conflict, err := uniqueIndexColumns(ctx, db)
	if err != nil {
		return 0, err
	}
	query := upsertSQL(columns, conflict)

	count, err := writeAll(ctx, db, query, columns, cookies, key)
	if err != nil {
		if isBusy(err) {
			return -1, nil
		}
		return 0, err
	}
	return count, nil
}

func writeAll(ctx context.Context, db *sql.DB, query string, columns []string, cookies []Cookie, key AesKey) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	for _, cookie := range cookies {
		encrypted, err := EncryptValue(cookie.Value, key, cookie.HostKey)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		values := insertValues(cookie, encrypted)
		args := make([]any, len(columns))
		for i, c := range columns {
			args[i] = sql.Named(c, values[c])
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(cookies), nil
}
