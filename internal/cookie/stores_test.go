package cookie

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// v18: carries is_same_party; UNIQUE(host_key, top_frame_site_key, name, path); no
// last_update_utc / source_type / has_cross_site_ancestor.
const v18SQL = `
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    is_same_party INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, name, path);
`

// v24: drops is_same_party, adds source_type + has_cross_site_ancestor + last_update_utc;
// UNIQUE(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port).
const v24SQL = `
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL,
    source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(
    host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
);
`

var schemas = map[string]string{"v18": v18SQL, "v24": v24SQL}

const (
	sampleCreation = ChromeMicros(13_300_000_000_000_000)
	sampleExpires  = ChromeMicros(13_400_000_000_000_000)
	sampleUpdate   = ChromeMicros(13_350_000_000_000_000)
)

func testKey(t *testing.T) AesKey {
	t.Helper()
	return DeriveKey(SafeStorageKey("peanuts"))
}

func makeBrowser(t *testing.T, root, profile string) Browser {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	return Browser{
		Name:            BrowserName("test"),
		Display:         "Test",
		DataRoot:        root,
		KeychainService: "Test Safe Storage",
	}
}

func initDB(t *testing.T, path, schemaSQL string) {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(schemaSQL); err != nil {
		t.Fatalf("exec schema: %v", err)
	}
}

func hasColumn(t *testing.T, path, column string) bool {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	cols, err := tableColumns(context.Background(), db)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	for _, c := range cols {
		if c == column {
			return true
		}
	}
	return false
}

const insertV18SQL = `INSERT INTO cookies (
    creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path,
    expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent,
    priority, samesite, source_scheme, source_port, is_same_party
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const insertV24SQL = `INSERT INTO cookies (
    creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path,
    expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent,
    priority, samesite, source_scheme, source_port, last_update_utc, source_type,
    has_cross_site_ancestor
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func insertV18(t *testing.T, exec func(string, ...any) (sql.Result, error), hostKey, name string, blob []byte) {
	t.Helper()
	if _, err := exec(
		insertV18SQL,
		int64(sampleCreation), hostKey, "", name, "", blob, "/",
		int64(sampleExpires), 1, 0, int64(sampleCreation), 1, 1, 1, 0, 2, 443, 0,
	); err != nil {
		t.Fatalf("insert v18: %v", err)
	}
}

func insertV24(t *testing.T, exec func(string, ...any) (sql.Result, error), hostKey, name string, blob []byte) {
	t.Helper()
	if _, err := exec(
		insertV24SQL,
		int64(sampleCreation), hostKey, "", name, "", blob, "/",
		int64(sampleExpires), 1, 0, int64(sampleCreation), 1, 1, 1, 0, 2, 443,
		int64(sampleUpdate), 0, 0,
	); err != nil {
		t.Fatalf("insert v24: %v", err)
	}
}

func insertNative(t *testing.T, path, hostKey, name string, blob []byte) {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if hasColumn(t, path, "last_update_utc") {
		insertV24(t, db.Exec, hostKey, name, blob)
	} else {
		insertV18(t, db.Exec, hostKey, name, blob)
	}
}

func sampleCookie(host, name, value string) Cookie {
	return Cookie{
		HostKey:       HostKey(host),
		Name:          name,
		Value:         value,
		Path:          "/",
		ExpiresUTC:    sampleExpires,
		LastUpdateUTC: sampleUpdate,
		CreationUTC:   sampleCreation,
		IsSecure:      true,
		IsHTTPOnly:    true,
		SameSite:      2,
	}
}

func mustEncrypt(t *testing.T, value string, key AesKey, host HostKey) []byte {
	t.Helper()
	blob, err := EncryptValue(value, key, host)
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	return blob
}

func mustDecrypt(t *testing.T, blob []byte, key AesKey, host HostKey) string {
	t.Helper()
	got, err := DecryptValue(blob, key, host)
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	return got
}

// forEachSchema runs fn against a fresh v18 and v24 cookie store, each in its own
// temp dir, so every behavior is proven against both Chrome schemas.
func forEachSchema(t *testing.T, fn func(t *testing.T, browser Browser, profile string)) {
	t.Helper()
	for name, schemaSQL := range schemas {
		t.Run(name, func(t *testing.T) {
			browser := makeBrowser(t, t.TempDir(), "Default")
			initDB(t, browser.CookiesDB("Default"), schemaSQL)
			fn(t, browser, "Default")
		})
	}
}

func TestReadReturnsInsertedRow(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		blob := mustEncrypt(t, "hello", key, HostKey(".x.com"))
		insertNative(t, browser.CookiesDB(profile), ".x.com", "sid", blob)

		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1", len(rows))
		}
		row := rows[0]
		if row.HostKey != ".x.com" {
			t.Errorf("host_key = %q, want .x.com", row.HostKey)
		}
		if row.Name != "sid" {
			t.Errorf("name = %q, want sid", row.Name)
		}
		if string(row.EncryptedValue) != string(blob) {
			t.Errorf("encrypted_value = %x, want %x", row.EncryptedValue, blob)
		}
		if got := mustDecrypt(t, row.EncryptedValue, key, row.HostKey); got != "hello" {
			t.Errorf("decrypted = %q, want hello", got)
		}
	})
}

func TestReadZeroFillsAbsentColumns(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		insertNative(t, browser.CookiesDB(profile), ".x.com", "sid", mustEncrypt(t, "v", key, HostKey(".x.com")))
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		row := rows[0]
		// Defaults that must hold regardless of schema (v18 lacks last_update_utc &
		// has_cross_site_ancestor; both seeds set source_scheme=2, source_port=443).
		if row.SourceScheme != 2 {
			t.Errorf("source_scheme = %d, want 2", row.SourceScheme)
		}
		if row.SourcePort != 443 {
			t.Errorf("source_port = %d, want 443", row.SourcePort)
		}
		if row.TopFrameSiteKey != "" {
			t.Errorf("top_frame_site_key = %q, want empty", row.TopFrameSiteKey)
		}
		if hasColumn(t, browser.CookiesDB(profile), "last_update_utc") {
			if row.LastUpdateUTC != sampleUpdate {
				t.Errorf("last_update_utc = %d, want %d", row.LastUpdateUTC, sampleUpdate)
			}
		} else if row.LastUpdateUTC != 0 {
			t.Errorf("v18 last_update_utc = %d, want 0 (zero-filled)", row.LastUpdateUTC)
		}
	})
}

func TestReadEmptyDB(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("got %d rows, want 0", len(rows))
		}
	})
}

// TestReadSeesWALSidecarRow proves modernc applies a row still pinned in an
// uncheckpointed -wal sidecar: a held read txn keeps the writer's close from
// checkpointing, so the row lives only in the -wal file the copy must read.
func TestReadSeesWALSidecarRow(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		dbPath := browser.CookiesDB(profile)
		blob := mustEncrypt(t, "wal-only", key, HostKey(".w.com"))

		writer, err := sql.Open(driverName, dbPath)
		if err != nil {
			t.Fatalf("open writer: %v", err)
		}
		if _, err := writer.Exec("PRAGMA journal_mode=WAL"); err != nil {
			t.Fatalf("journal_mode: %v", err)
		}
		if _, err := writer.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
			t.Fatalf("wal_autocheckpoint: %v", err)
		}

		holder, err := sql.Open(driverName, dbPath)
		if err != nil {
			t.Fatalf("open holder: %v", err)
		}
		htx, err := holder.Begin()
		if err != nil {
			t.Fatalf("holder begin: %v", err)
		}
		if err := htx.QueryRow("SELECT count(*) FROM cookies").Scan(new(int)); err != nil {
			t.Fatalf("holder read: %v", err)
		}

		if hasColumn(t, dbPath, "last_update_utc") {
			insertV24(t, writer.Exec, ".w.com", "sid", blob)
		} else {
			insertV18(t, writer.Exec, ".w.com", "sid", blob)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("writer close: %v", err)
		}

		if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
			t.Fatalf("-wal sidecar missing or empty: err=%v", err)
		}

		// The row must live ONLY in the -wal sidecar: a copy of the main DB file
		// alone (no sidecars) must not see it, proving WAL handling is load-bearing.
		mainOnly := filepath.Join(t.TempDir(), "Cookies")
		//nolint:gosec // G304/G703: dbPath and mainOnly are t.TempDir()-derived test paths, not user-supplied.
		if data, rerr := os.ReadFile(dbPath); rerr != nil {
			t.Fatalf("read main db: %v", rerr)
		} else if werr := os.WriteFile(mainOnly, data, 0o600); werr != nil {
			t.Fatalf("write main-only copy: %v", werr)
		}
		mdb, err := sql.Open(driverName, mainOnly)
		if err != nil {
			t.Fatalf("open main-only: %v", err)
		}
		var mainCount int
		if err := mdb.QueryRow("SELECT count(*) FROM cookies").Scan(&mainCount); err != nil {
			t.Fatalf("count main-only: %v", err)
		}
		_ = mdb.Close()
		if mainCount != 0 {
			t.Fatalf("main DB alone has %d rows, want 0 (row should be WAL-only)", mainCount)
		}

		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		_ = htx.Rollback()
		_ = holder.Close()

		if len(rows) != 1 || rows[0].Name != "sid" {
			t.Fatalf("got %d rows %+v, want 1 named sid", len(rows), rows)
		}
		if got := mustDecrypt(t, rows[0].EncryptedValue, key, rows[0].HostKey); got != "wal-only" {
			t.Errorf("decrypted = %q, want wal-only", got)
		}
	})
}

func TestWriteInsertsThenUpsertsToSingleRow(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		first := sampleCookie(".example.com", "sid", "v1")
		if n, err := Write(context.Background(), browser, profile, []Cookie{first}, key); err != nil || n != 1 {
			t.Fatalf("first Write = (%d, %v), want (1, nil)", n, err)
		}
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("after insert: got %d rows, want 1", len(rows))
		}
		if got := mustDecrypt(t, rows[0].EncryptedValue, key, rows[0].HostKey); got != "v1" {
			t.Errorf("decrypted = %q, want v1", got)
		}

		second := first
		second.Value = "v2-newest"
		if n, err := Write(context.Background(), browser, profile, []Cookie{second}, key); err != nil || n != 1 {
			t.Fatalf("second Write = (%d, %v), want (1, nil)", n, err)
		}
		rows, err = Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("conflict on the real unique index must collapse to one row; got %d", len(rows))
		}
		if got := mustDecrypt(t, rows[0].EncryptedValue, key, rows[0].HostKey); got != "v2-newest" {
			t.Errorf("decrypted = %q, want v2-newest", got)
		}
	})
}

func TestWriteLeavesPlaintextValueEmpty(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		if _, err := Write(context.Background(), browser, profile, []Cookie{sampleCookie(".example.com", "sid", "secret")}, key); err != nil {
			t.Fatalf("Write: %v", err)
		}
		db, err := sql.Open(driverName, browser.CookiesDB(profile))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = db.Close() }()
		var value string
		var enc []byte
		if err := db.QueryRow("SELECT value, encrypted_value FROM cookies").Scan(&value, &enc); err != nil {
			t.Fatalf("select: %v", err)
		}
		if value != "" {
			t.Errorf("plaintext value = %q, want empty", value)
		}
		if len(enc) < 3 || string(enc[:3]) != "v10" {
			t.Fatalf("encrypted_value missing v10 prefix: %x", enc)
		}
		if got := mustDecrypt(t, enc, key, HostKey(".example.com")); got != "secret" {
			t.Errorf("decrypted = %q, want secret", got)
		}
	})
}

func TestWritePreservesLastUpdateAndCreation(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		cookie := sampleCookie(".example.com", "sid", "v")
		if _, err := Write(context.Background(), browser, profile, []Cookie{cookie}, key); err != nil {
			t.Fatalf("Write: %v", err)
		}
		db, err := sql.Open(driverName, browser.CookiesDB(profile))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = db.Close() }()
		var creation int64
		if err := db.QueryRow("SELECT creation_utc FROM cookies").Scan(&creation); err != nil {
			t.Fatalf("select creation: %v", err)
		}
		if creation != int64(cookie.CreationUTC) {
			t.Errorf("creation_utc = %d, want %d (must be preserved, not stamped now)", creation, cookie.CreationUTC)
		}
		if hasColumn(t, browser.CookiesDB(profile), "last_update_utc") {
			var lu int64
			if err := db.QueryRow("SELECT last_update_utc FROM cookies").Scan(&lu); err != nil {
				t.Fatalf("select last_update: %v", err)
			}
			if lu != int64(cookie.LastUpdateUTC) {
				t.Errorf("last_update_utc = %d, want %d (must be preserved, not now)", lu, cookie.LastUpdateUTC)
			}
		}
	})
}

func TestUpsertUpdatesExpiryAndFlags(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		if _, err := Write(context.Background(), browser, profile, []Cookie{sampleCookie(".example.com", "sid", "v1")}, key); err != nil {
			t.Fatalf("Write v1: %v", err)
		}
		refreshed := sampleCookie(".example.com", "sid", "v2")
		refreshed.ExpiresUTC = ChromeMicros(13_999_000_000_000_000)
		refreshed.IsHTTPOnly = false
		refreshed.SameSite = 0
		if _, err := Write(context.Background(), browser, profile, []Cookie{refreshed}, key); err != nil {
			t.Fatalf("Write v2: %v", err)
		}
		db, err := sql.Open(driverName, browser.CookiesDB(profile))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = db.Close() }()
		var expires, httponly, samesite int64
		if err := db.QueryRow("SELECT expires_utc, is_httponly, samesite FROM cookies").Scan(&expires, &httponly, &samesite); err != nil {
			t.Fatalf("select: %v", err)
		}
		if expires != 13_999_000_000_000_000 {
			t.Errorf("expires_utc = %d, want 13999000000000000", expires)
		}
		if httponly != 0 {
			t.Errorf("is_httponly = %d, want 0", httponly)
		}
		if samesite != 0 {
			t.Errorf("samesite = %d, want 0", samesite)
		}
	})
}

func TestFullRoundtripPreservesValueAndFlags(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		original := sampleCookie(".roundtrip.test", "auth", "café—token—😀")
		if _, err := Write(context.Background(), browser, profile, []Cookie{original}, key); err != nil {
			t.Fatalf("Write: %v", err)
		}
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1", len(rows))
		}
		row := rows[0]
		if got := mustDecrypt(t, row.EncryptedValue, key, row.HostKey); got != original.Value {
			t.Errorf("decrypted = %q, want %q", got, original.Value)
		}
		if row.HostKey != original.HostKey {
			t.Errorf("host_key = %q, want %q", row.HostKey, original.HostKey)
		}
		if row.Name != original.Name {
			t.Errorf("name = %q, want %q", row.Name, original.Name)
		}
		if row.Path != original.Path {
			t.Errorf("path = %q, want %q", row.Path, original.Path)
		}
		if row.ExpiresUTC != original.ExpiresUTC {
			t.Errorf("expires_utc = %d, want %d", row.ExpiresUTC, original.ExpiresUTC)
		}
		if row.IsSecure != original.IsSecure {
			t.Errorf("is_secure = %v, want %v", row.IsSecure, original.IsSecure)
		}
		if row.IsHTTPOnly != original.IsHTTPOnly {
			t.Errorf("is_httponly = %v, want %v", row.IsHTTPOnly, original.IsHTTPOnly)
		}
		if row.SameSite != original.SameSite {
			t.Errorf("samesite = %d, want %d", row.SameSite, original.SameSite)
		}

		reencrypted := original
		reencrypted.Value = mustDecrypt(t, row.EncryptedValue, key, row.HostKey)
		if _, err := Write(context.Background(), browser, profile, []Cookie{reencrypted}, key); err != nil {
			t.Fatalf("re-Write: %v", err)
		}
		rows2, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("re-Read: %v", err)
		}
		if len(rows2) != 1 {
			t.Fatalf("got %d rows after re-write, want 1", len(rows2))
		}
		if got := mustDecrypt(t, rows2[0].EncryptedValue, key, rows2[0].HostKey); got != original.Value {
			t.Errorf("re-read decrypted = %q, want %q", got, original.Value)
		}
	})
}

func TestMultipleDistinctCookiesCoexist(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		cookies := []Cookie{
			sampleCookie(".a.com", "x", "1"),
			sampleCookie(".a.com", "y", "2"),
			sampleCookie(".b.com", "x", "3"),
		}
		if n, err := Write(context.Background(), browser, profile, cookies, key); err != nil || n != 3 {
			t.Fatalf("Write = (%d, %v), want (3, nil)", n, err)
		}
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(rows) != 3 {
			t.Fatalf("got %d rows, want 3", len(rows))
		}
		got := map[string]bool{}
		for _, r := range rows {
			got[mustDecrypt(t, r.EncryptedValue, key, r.HostKey)] = true
		}
		for _, want := range []string{"1", "2", "3"} {
			if !got[want] {
				t.Errorf("missing decrypted value %q in %v", want, got)
			}
		}
	})
}

// TestWriteSoftBusyReturnsMinusOne holds an uncommitted write transaction on a
// second connection so the live DB is locked; Write must return -1 (soft busy),
// never an error and never a clobber.
func TestWriteSoftBusyReturnsMinusOne(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := testKey(t)
		dbPath := browser.CookiesDB(profile)

		locker, err := sql.Open(driverName, dbPath)
		if err != nil {
			t.Fatalf("open locker: %v", err)
		}
		defer func() { _ = locker.Close() }()
		ltx, err := locker.Begin()
		if err != nil {
			t.Fatalf("locker begin: %v", err)
		}
		// Take a write lock on the database that outlives the Write attempt.
		if hasColumn(t, dbPath, "last_update_utc") {
			insertV24(t, ltx.Exec, ".lock.com", "held", mustEncrypt(t, "x", key, HostKey(".lock.com")))
		} else {
			insertV18(t, ltx.Exec, ".lock.com", "held", mustEncrypt(t, "x", key, HostKey(".lock.com")))
		}

		n, err := Write(context.Background(), browser, profile, []Cookie{sampleCookie(".example.com", "sid", "v")}, key)
		if err != nil {
			t.Fatalf("Write returned error on locked DB, want soft -1: %v", err)
		}
		if n != -1 {
			t.Fatalf("Write = %d on locked DB, want -1", n)
		}
		if err := ltx.Rollback(); err != nil {
			t.Fatalf("rollback: %v", err)
		}

		// Soft busy must not clobber: the rejected Write rolled back, so its row is
		// absent (and the locker's uncommitted row rolled back too) — DB is empty.
		rows, err := Read(context.Background(), browser, profile)
		if err != nil {
			t.Fatalf("Read after soft-busy: %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("soft-busy clobbered the DB: got %d rows, want 0", len(rows))
		}
	})
}

func TestReadCleansUpTempDir(t *testing.T) {
	browser := makeBrowser(t, t.TempDir(), "Default")
	initDB(t, browser.CookiesDB("Default"), v24SQL)
	before := tempDirCount(t)
	if _, err := Read(context.Background(), browser, "Default"); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if after := tempDirCount(t); after != before {
		t.Errorf("cookiesync-* temp dirs leaked: before=%d after=%d", before, after)
	}
}

func tempDirCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) >= 11 && e.Name()[:11] == "cookiesync-" {
			n++
		}
	}
	return n
}
