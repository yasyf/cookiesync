package cookie

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

type rawRow struct {
	Value     string
	Encrypted []byte
}

func newLinuxStore(t *testing.T, metaVersion int) (Browser, string) {
	t.Helper()
	browser := makeBrowser(t, t.TempDir(), "Default")
	path := browser.CookiesDB("Default")
	initDB(t, path, v24SQL)
	if metaVersion != 0 {
		setMetaVersion(t, path, metaVersion)
	}
	return browser, path
}

func setMetaVersion(t *testing.T, path string, version int) {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)"); err != nil {
		t.Fatalf("create meta: %v", err)
	}
	if version < 0 {
		return
	}
	if _, err := db.Exec("INSERT INTO meta(key, value) VALUES('version', ?), ('last_compatible_version', ?)", version, version); err != nil {
		t.Fatalf("set version: %v", err)
	}
}

func rawRows(t *testing.T, path string) map[string]rawRow {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("SELECT name, value, encrypted_value FROM cookies")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]rawRow{}
	for rows.Next() {
		var (
			name string
			row  rawRow
		)
		if err := rows.Scan(&name, &row.Value, &row.Encrypted); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[name] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

func TestSchemeLinuxReadDecryptsEveryTagTheStoreUses(t *testing.T) {
	for _, version := range []int{23, 24} {
		browser, path := newLinuxStore(t, version)
		insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", version))
		insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", version))
		rows, err := linuxCodec.read(context.Background(), browser, "Default")
		if err != nil {
			t.Fatalf("meta %d: read: %v", version, err)
		}
		for _, row := range rows {
			if row.metaVersion != version {
				t.Fatalf("row %s carries store version %d, want %d", row.Name, row.metaVersion, version)
			}
		}
		cookies, counts, err := linuxCodec.decryptRows(rows, keyringKey(t))
		if err != nil || counts != (DecryptCounts{}) || len(cookies) != 2 {
			t.Fatalf("meta %d: decryptRows = %d cookies, %+v, %v", version, len(cookies), counts, err)
		}
		state, err := linuxCodec.extract(context.Background(), "https://x.com/", browser, keyringKey(t), "Default", true, false)
		if err != nil || len(state.Cookies) != 2 {
			t.Fatalf("meta %d: extract = %d cookies, %v", version, len(state.Cookies), err)
		}
	}
}

func TestSchemeLinuxKeyringRowsFailTheWholeReadWithoutTheKey(t *testing.T) {
	browser, path := newLinuxStore(t, 24)
	insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
	insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
	rows, err := linuxCodec.read(context.Background(), browser, "Default")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cookies, _, err := linuxCodec.decryptRows(rows, linuxBasicKey); !errors.Is(err, ErrV11KeyUnavailable) || cookies != nil {
		t.Fatalf("decryptRows = %v, %v; want ErrV11KeyUnavailable and no cookies", cookies, err)
	}
	if state, err := linuxCodec.extract(context.Background(), "https://x.com/", browser, linuxBasicKey, "Default", true, false); !errors.Is(err, ErrV11KeyUnavailable) || len(state.Cookies) != 0 {
		t.Fatalf("extract = %v, %v; want ErrV11KeyUnavailable and no cookies", state.Cookies, err)
	}
	if state, counts, err := linuxCodec.seedState(context.Background(), browser, "Default", linuxBasicKey); !errors.Is(err, ErrV11KeyUnavailable) || len(state.Cookies) != 0 || counts != (SeedCounts{}) {
		t.Fatalf("seedState = %v, %+v, %v; want ErrV11KeyUnavailable", state.Cookies, counts, err)
	}
}

func TestSchemeLinuxReadRequiresMetaVersion(t *testing.T) {
	for _, c := range []struct {
		id      string
		version int
	}{{"no-meta-table", 0}, {"no-version-row", -1}} {
		t.Run(c.id, func(t *testing.T) {
			browser, path := newLinuxStore(t, c.version)
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
			if _, err := linuxCodec.read(context.Background(), browser, "Default"); !errors.Is(err, ErrStoreVersionUnknown) {
				t.Fatalf("read: got %v, want ErrStoreVersionUnknown", err)
			}
			if _, err := darwinCodec.read(context.Background(), browser, "Default"); err != nil {
				t.Fatalf("the Darwin scheme never consults meta: %v", err)
			}
		})
	}
}

func TestSchemeLinuxWriteRefusals(t *testing.T) {
	cases := []struct {
		id      string
		version int
		seed    func(t *testing.T, path string)
		key     AesKey
		wantErr error
	}{
		{"empty-store", 24, func(*testing.T, string) {}, linuxBasicKey, ErrStoreTagUnknown},
		{"portal-rows", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "portal", append([]byte("v12"), bytes.Repeat([]byte{0x01}, 28)...))
		}, keyringKey(t), ErrStoreTagUnmatched},
		{"basic-and-unknown-rows", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
			insertNative(t, path, ".x.com", "odd", []byte("not-a-chromium-blob"))
		}, linuxBasicKey, ErrStoreTagUnmatched},
		{"keyring-store-basic-key", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, linuxBasicKey, ErrV11KeyUnavailable},
		{"mixed-store-basic-key", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, linuxBasicKey, ErrV11KeyUnavailable},
		{"keyring-store-wrong-key", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, otherKeyringKey(t), ErrStoreKeyMismatch},
		{"no-meta-version", 0, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
		}, linuxBasicKey, ErrStoreVersionUnknown},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			browser, path := newLinuxStore(t, c.version)
			c.seed(t, path)
			before := rawRows(t, path)
			count, err := linuxCodec.write(context.Background(), browser, "Default", []Cookie{sampleCookie(".x.com", "new", "value")}, c.key)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("write: got %v, want %v", err, c.wantErr)
			}
			if count != 0 {
				t.Fatalf("refused write reported %d rows", count)
			}
			if after := rawRows(t, path); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused write changed the store: before %v, after %v", before, after)
			}
		})
	}
}

func TestSchemeLinuxWriteMatchesTheStoreTag(t *testing.T) {
	cases := []struct {
		id      string
		version int
		seed    func(t *testing.T, path string)
		key     AesKey
		wantTag string
		openKey AesKey
	}{
		{"basic-store-basic-key", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
		}, linuxBasicKey, "v10", linuxBasicKey},
		{"basic-store-keyring-key", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
		}, keyringKey(t), "v10", linuxBasicKey},
		{"keyring-store", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, keyringKey(t), "v11", keyringKey(t)},
		{"keyring-store-with-stale-row", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "stale", linuxSealed(t, "v11", otherKeyringKey(t), "old", ".x.com", 24))
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, keyringKey(t), "v11", keyringKey(t)},
		{"mixed-store", 24, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 24))
			insertNative(t, path, ".x.com", "keyring", linuxSealed(t, "v11", keyringKey(t), "two", ".x.com", 24))
		}, keyringKey(t), "v11", keyringKey(t)},
		{"legacy-store-without-hash", 23, func(t *testing.T, path string) {
			insertNative(t, path, ".x.com", "basic", linuxSealed(t, "v10", linuxBasicKey, "one", ".x.com", 23))
		}, linuxBasicKey, "v10", linuxBasicKey},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			browser, path := newLinuxStore(t, c.version)
			c.seed(t, path)
			count, err := linuxCodec.write(context.Background(), browser, "Default", []Cookie{sampleCookie(".x.com", "new", "value")}, c.key)
			if err != nil || count != 1 {
				t.Fatalf("write = %d, %v; want 1 row", count, err)
			}
			row := rawRows(t, path)["new"]
			if row.Value != "" || !bytes.HasPrefix(row.Encrypted, []byte(c.wantTag)) {
				t.Fatalf("row = value %q, encrypted %x; want empty value under %s", row.Value, row.Encrypted, c.wantTag)
			}
			got, err := lnx.open(row.Encrypted, c.openKey, ".x.com", c.version)
			if err != nil || got != "value" {
				t.Fatalf("open written row = %q, %v", got, err)
			}
			if got, err := lnx.open(row.Encrypted, c.openKey, ".x.com", 47-c.version); err == nil && got == "value" {
				t.Fatalf("written row opens under the wrong hash-prefix rule (meta %d)", c.version)
			}
		})
	}
}

func TestSchemeLinuxUpsertClearsPlaintextValue(t *testing.T) {
	browser, path := newLinuxStore(t, 24)
	insertNative(t, path, ".x.com", "sid", linuxSealed(t, "v10", linuxBasicKey, "old", ".x.com", 24))
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("UPDATE cookies SET value = 'leaked' WHERE name = 'sid'"); err != nil {
		t.Fatalf("plant plaintext: %v", err)
	}
	_ = db.Close()
	newer := sampleCookie(".x.com", "sid", "fresh")
	newer.LastUpdateUTC = sampleUpdate + 1
	if count, err := linuxCodec.write(context.Background(), browser, "Default", []Cookie{newer}, linuxBasicKey); err != nil || count != 1 {
		t.Fatalf("write = %d, %v", count, err)
	}
	row := rawRows(t, path)["sid"]
	if row.Value != "" {
		t.Fatalf("value column = %q after upsert, want empty", row.Value)
	}
	if got, err := lnx.open(row.Encrypted, linuxBasicKey, ".x.com", 24); err != nil || got != "fresh" {
		t.Fatalf("open = %q, %v; want fresh", got, err)
	}
}

func TestSchemeLinuxWriteOfNothingNeedsNoTag(t *testing.T) {
	browser, path := newLinuxStore(t, 0)
	if count, err := linuxCodec.write(context.Background(), browser, "Default", nil, linuxBasicKey); err != nil || count != 0 {
		t.Fatalf("empty write = %d, %v", count, err)
	}
	if rows := rawRows(t, path); len(rows) != 0 {
		t.Fatalf("empty write left %d rows", len(rows))
	}
}
