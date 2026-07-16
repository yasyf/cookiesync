package cookie

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite" // registers the "sqlite" database/sql driver
	sqlite3 "modernc.org/sqlite/lib"
)

// Schema-version-aware I/O against Chrome's cookie store: reads snapshot the live
// DB with a read-only VACUUM INTO; writes upsert in an IMMEDIATE transaction.

const (
	driverName    = "sqlite"
	busyTimeoutMS = 250
)

var errNoCookiesTable = errors.New("cookies table is unreadable or absent")

// ErrStoreBusy signals that a cookie store could not be snapshotted because the
// owning browser is mid-write: a hot rollback journal a read-only connection may not
// recover, or a held lock. Callers branch on it with errors.Is and retry after the
// browser quiesces rather than falling back to a torn byte copy.
var ErrStoreBusy = errors.New("cookie store busy: owning browser is mid-write")

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

func snapshotBusy(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	if serr.Code() == sqlite3.SQLITE_READONLY_ROLLBACK {
		return true
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, errNoCookiesTable
	}
	return columns, nil
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

// VACUUM INTO over a read-only connection takes proper shared locks, so a browser
// mid-write is snapshotted consistently rather than byte-copied into a torn image.
func snapshotDB(ctx context.Context, src, dst string) error {
	db, err := sql.Open(driverName, "file:"+src+"?mode=ro")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		if snapshotBusy(err) {
			return ErrStoreBusy
		}
		return fmt.Errorf("snapshot cookie store: %w", err)
	}
	return nil
}

// Read returns every cookie row in profile as a raw EncryptedRow, read off a
// consistent snapshot of the live store taken with VACUUM INTO on a read-only
// connection — a browser mid-write is captured through proper shared locks,
// including rows still pending in an uncheckpointed WAL, rather than as a torn byte
// copy, and the snapshot is opened immutable. Only columns present in this store's
// schema are selected; absent columns fall back to their defaults.
func Read(ctx context.Context, browser Browser, profile string) ([]EncryptedRow, error) {
	tmpDir, err := os.MkdirTemp("", "cookiesync-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	snapshot := filepath.Join(tmpDir, "Cookies")
	if err := snapshotDB(ctx, browser.CookiesDB(profile), snapshot); err != nil {
		return nil, err
	}

	db, err := sql.Open(driverName, "file:"+snapshot+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

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

func upsertSQL(columns, conflict []string) (string, error) {
	if len(columns) == 0 {
		return "", errNoCookiesTable
	}
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
	query := fmt.Sprintf(
		"INSERT INTO cookies (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
		strings.Join(conflict, ", "),
		strings.Join(updates, ", "),
	)
	if _, ok := conflictSet["last_update_utc"]; ok {
		query += " WHERE excluded.last_update_utc > cookies.last_update_utc"
	}
	return query, nil
}

// Write encrypts and upserts cookies into profile's live Cookies DB and returns
// the number of rows actually inserted or updated. Each value is re-encrypted
// into a v10 blob, leaving the plaintext value column empty. On stores with a
// last_update_utc column, a conflict updates the on-disk row only when the
// incoming timestamp is strictly newer; an equal or older timestamp is a no-op.
// Cookie timestamps are preserved, never stamped to "now". On a locked database
// this returns -1 (soft busy) rather than forcing a write.
func Write(ctx context.Context, browser Browser, profile string, cookies []Cookie, key AesKey) (int, error) {
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=busy_timeout(%d)", browser.CookiesDB(profile), busyTimeoutMS)
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()

	columns, err := tableColumns(ctx, db)
	if err != nil {
		return 0, err
	}
	conflict, err := uniqueIndexColumns(ctx, db)
	if err != nil {
		return 0, err
	}
	query, err := upsertSQL(columns, conflict)
	if err != nil {
		return 0, err
	}

	count, err := writeAll(ctx, db, query, columns, cookies, key)
	if err != nil {
		if isBusy(err) {
			slog.WarnContext(ctx, "cookie store busy; skipping write", "browser", browser.Name, "profile", profile)
			return -1, nil
		}
		return 0, err
	}
	return count, nil
}

func writeAll(ctx context.Context, db *sql.DB, query string, columns []string, cookies []Cookie, key AesKey) (int, error) {
	// BEGIN IMMEDIATE (via _txlock=immediate in the DSN): fail-fast on a locked DB
	// rather than a DEFERRED tx that upgrades to a write lock mid-loop.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	count := 0
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
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		count += int(affected)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}
