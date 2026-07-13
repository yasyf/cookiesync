package cookie

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Read-only capture of a Chromium browser's web storage out of its LevelDB stores. Both
// stores are copied to a temp dir and the copy is opened read-only, so a running
// browser's LOCK is never taken. Local Storage keys are "_<origin>\x00<key>"; script
// keys and values carry Chrome's String16 marker byte (0x00 UTF-16LE, 0x01 Latin-1).
// Session Storage indirects namespace-<nsid>-<origin> -> map-id then map-<map-id>-<key>
// -> value, whose values are 0x01/Latin-1 or a markerless raw UTF-16LE payload.
// Partitioned "^N" StorageKeys are skipped: only first-party storage is captured.
// IndexedDB is out of scope: its idb_cmp1 comparator and V8 values need a bespoke reader.

const (
	// lsDataPrefix leads every Local Storage script-value key; metadata keys (VERSION,
	// META:, METAACCESS:) never carry it.
	lsDataPrefix = '_'
	// strMarkerUTF16/strMarkerLatin1 are Chrome's String16 encoding markers: the first
	// byte of an encoded key or value.
	strMarkerUTF16  = 0x00
	strMarkerLatin1 = 0x01
)

// decodeUTF16LE decodes a little-endian UTF-16 byte run; a trailing odd byte is dropped.
func decodeUTF16LE(b []byte) string {
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u16))
}

// decodeLatin1 decodes an ISO-8859-1 byte run: each byte is one Unicode code point.
func decodeLatin1(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

// decodeLSValue decodes a Local Storage String16 blob by its leading marker byte: 0x00
// is UTF-16LE, anything else (0x01) is Latin-1. An empty blob is the empty string.
func decodeLSValue(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == strMarkerUTF16 {
		return decodeUTF16LE(b[1:])
	}
	return decodeLatin1(b[1:])
}

// decodeSSValue decodes a Session Storage value: a 0x00 marker is UTF-16LE, 0x01 is
// Latin-1, and any other leading byte is a markerless raw UTF-16LE payload.
func decodeSSValue(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case strMarkerUTF16:
		return decodeUTF16LE(b[1:])
	case strMarkerLatin1:
		return decodeLatin1(b[1:])
	default:
		return decodeUTF16LE(b)
	}
}

// parseLocalStorageKey splits a Local Storage data key "_<origin>\x00<marker><key>" into
// the exact origin string and the decoded script key. A non-data key (VERSION, META:*, a
// partitioned "^N" StorageKey) — anything not led by '_', missing the NUL separator, or
// carrying partition attributes on its origin — returns ok=false.
func parseLocalStorageKey(key []byte) (origin, scriptKey string, ok bool) {
	if len(key) == 0 || key[0] != lsDataPrefix {
		return "", "", false
	}
	rest := key[1:]
	nul := bytes.IndexByte(rest, 0x00)
	if nul < 0 {
		return "", "", false
	}
	origin = string(rest[:nul])
	if isPartitionedKey(origin) {
		return "", "", false
	}
	return origin, decodeLSValue(rest[nul+1:]), true
}

// parseNamespaceOrigin extracts the exact origin from a Session Storage
// "namespace-<nsid>-<origin>" key. The origin begins at its scheme, which the namespace
// id never contains, so the first "://" locates it. Keys without an origin (the
// next-map-id counter, the empty namespace) and partitioned "^N" StorageKeys return
// ok=false.
func parseNamespaceOrigin(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "namespace-")
	if !ok {
		return "", false
	}
	scheme := strings.Index(rest, "://")
	if scheme < 0 {
		return "", false
	}
	start := scheme
	for start > 0 && isSchemeByte(rest[start-1]) {
		start--
	}
	if start == 0 || rest[start-1] != '-' {
		return "", false
	}
	origin := rest[start:]
	if isPartitionedKey(origin) {
		return "", false
	}
	return origin, true
}

func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isPartitionedKey reports whether a stored origin carries "^N" StorageKey partition
// attributes (top-level site, nonce, ancestor bit) — partitioned storage, not
// first-party. Chromium never emits "^" inside a serialized bare origin.
func isPartitionedKey(origin string) bool { return strings.ContainsRune(origin, '^') }

// copyDir copies a browser LevelDB directory (Local Storage / Session Storage) into
// destDir so a running browser's LOCK is never taken. A LevelDB dir is flat — CURRENT,
// MANIFEST-*, *.ldb, *.log, LOG — so the LOCK file and any subdirectory are skipped.
// Both paths are the tool's own resolved layout, never user-supplied.
func copyDir(src, destDir string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "LOCK" {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(destDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// openCopiedLevelDB copies dir into a fresh temp dir and opens the copy read-only, so a
// running browser is never disturbed. The returned closer closes the db and removes the
// temp dir; callers defer it.
func openCopiedLevelDB(dir string) (*leveldb.DB, func(), error) {
	tmp, err := os.MkdirTemp("", "cookiesync-ws-")
	if err != nil {
		return nil, nil, err
	}
	if err := copyDir(dir, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, nil, err
	}
	db, err := leveldb.OpenFile(tmp, &opt.Options{ReadOnly: true})
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, nil, fmt.Errorf("open leveldb %s: %w", dir, err)
	}
	return db, func() { _ = db.Close(); _ = os.RemoveAll(tmp) }, nil
}

// ReadLocalStorage decodes every origin's Local Storage from profile in b, keyed by the
// exact origin string (scheme+host+port) the browser recorded. Metadata keys are
// skipped, and each value is decoded by its String16 marker byte. A profile with no
// Local Storage yields an empty map. It reads a private copy, honoring ctx.
func ReadLocalStorage(ctx context.Context, b Browser, profile string) (map[string][]WebStorageEntry, error) {
	dir := b.LocalStorageDir(profile)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return map[string][]WebStorageEntry{}, nil
	}
	db, closeDB, err := openCopiedLevelDB(dir)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	out := map[string][]WebStorageEntry{}
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		origin, name, ok := parseLocalStorageKey(iter.Key())
		if !ok {
			continue
		}
		out[origin] = append(out[origin], WebStorageEntry{Name: name, Value: decodeLSValue(iter.Value())})
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate local storage: %w", err)
	}
	return out, nil
}

// ReadSessionStorage decodes every origin's Session Storage from profile in b, keyed by
// the exact origin string the browser recorded (a trailing "/" and all). Each open tab
// is its own namespace/map for an origin; their maps are unioned with the first
// namespace's value winning per key. A profile with no Session Storage yields an empty
// map. It reads a private copy, honoring ctx.
func ReadSessionStorage(ctx context.Context, b Browser, profile string) (map[string][]WebStorageEntry, error) {
	dir := b.SessionStorageDir(profile)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return map[string][]WebStorageEntry{}, nil
	}
	db, closeDB, err := openCopiedLevelDB(dir)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	mapIDs, err := sessionMapIDs(ctx, db)
	if err != nil {
		return nil, err
	}
	out := map[string][]WebStorageEntry{}
	for origin, ids := range mapIDs {
		entries, err := sessionEntries(ctx, db, ids)
		if err != nil {
			return nil, err
		}
		out[origin] = entries
	}
	return out, nil
}

// sessionMapIDs reads the namespace index into origin -> map ids, one entry per open
// tab's namespace, in namespace-key (sorted) order.
func sessionMapIDs(ctx context.Context, db *leveldb.DB) (map[string][]string, error) {
	mapIDs := map[string][]string{}
	iter := db.NewIterator(util.BytesPrefix([]byte("namespace-")), nil)
	defer iter.Release()
	for iter.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		origin, ok := parseNamespaceOrigin(string(iter.Key()))
		if !ok {
			continue
		}
		if mapID := string(iter.Value()); mapID != "" {
			mapIDs[origin] = append(mapIDs[origin], mapID)
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate session namespaces: %w", err)
	}
	return mapIDs, nil
}

// sessionEntries reads and unions the map-<id>-<key> rows for one origin's map ids, first
// value winning per key, returned sorted by name.
func sessionEntries(ctx context.Context, db *leveldb.DB, ids []string) ([]WebStorageEntry, error) {
	seen := map[string]bool{}
	var entries []WebStorageEntry
	for _, id := range ids {
		prefix := []byte("map-" + id + "-")
		iter := db.NewIterator(util.BytesPrefix(prefix), nil)
		for iter.Next() {
			if err := ctx.Err(); err != nil {
				iter.Release()
				return nil, err
			}
			name := string(iter.Key()[len(prefix):])
			if seen[name] {
				continue
			}
			seen[name] = true
			entries = append(entries, WebStorageEntry{Name: name, Value: decodeSSValue(iter.Value())})
		}
		iter.Release()
		if err := iter.Error(); err != nil {
			return nil, fmt.Errorf("iterate session map %s: %w", id, err)
		}
	}
	sortEntries(entries)
	return entries, nil
}

// canonicalOrigin normalizes a stored origin to its scheme://host[:port] form: Session
// Storage serializes the origin with a trailing "/", Local Storage does not, so the same
// origin collapses to one key.
func canonicalOrigin(origin string) string {
	return strings.TrimSuffix(origin, "/")
}

// ExtractWebStorage reads the localStorage and sessionStorage for every origin whose host
// matches one of urls' hosts, from profile in b. Origins are matched by NormalizeHost but
// the exact origin string (scheme+host+port) is preserved for injection; Local and
// Session Storage for one origin collapse onto its canonical form. Returns one
// OriginStorage per matched origin, sorted by origin, each with name-sorted entries.
func ExtractWebStorage(ctx context.Context, urls []string, b Browser, profile string) ([]OriginStorage, error) {
	local, err := ReadLocalStorage(ctx, b, profile)
	if err != nil {
		return nil, err
	}
	session, err := ReadSessionStorage(ctx, b, profile)
	if err != nil {
		return nil, err
	}
	hosts := map[Host]bool{}
	for _, u := range urls {
		hosts[NormalizeHost(u)] = true
	}
	origins := map[string]*OriginStorage{}
	keep := func(rawOrigin string) *OriginStorage {
		if !hosts[NormalizeHost(rawOrigin)] {
			return nil
		}
		origin := canonicalOrigin(rawOrigin)
		o, ok := origins[origin]
		if !ok {
			o = &OriginStorage{Origin: origin}
			origins[origin] = o
		}
		return o
	}
	for origin, entries := range local {
		if o := keep(origin); o != nil {
			o.LocalStorage = append(o.LocalStorage, entries...)
		}
	}
	for origin, entries := range session {
		if o := keep(origin); o != nil {
			o.SessionStorage = append(o.SessionStorage, entries...)
		}
	}
	out := make([]OriginStorage, 0, len(origins))
	for _, o := range origins {
		sortEntries(o.LocalStorage)
		sortEntries(o.SessionStorage)
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out, nil
}

func sortEntries(entries []WebStorageEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
}
