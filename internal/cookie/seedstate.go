package cookie

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// SeedCounts tallies why each cookie row in a profile was kept or dropped during a
// seed: Attempted is every row read, Undecryptable the rows DecryptRow could not
// decrypt, Expired the decrypted rows isLive dropped. The kept cookies
// (Attempted - Undecryptable - Expired) travel in the StorageState.
type SeedCounts struct {
	Attempted     int
	Undecryptable int
	Expired       int
}

// SeedState decrypts every cookie and all local/session storage in a profile for bridge seeding.
// It returns the full StorageState plus a per-cause count of the cookie rows it dropped (a caller may
// fail loud on a materially incomplete clone). key must already be released by the consent layer.
func SeedState(ctx context.Context, browser Browser, profile string, key AesKey) (state StorageState, counts SeedCounts, err error) {
	rows, err := Read(ctx, browser, profile)
	if err != nil {
		return StorageState{}, SeedCounts{}, fmt.Errorf("read cookies: %w", err)
	}

	now := float64(time.Now().UnixNano()) / 1e9
	counts.Attempted = len(rows)
	cookies := make([]Cookie, 0, len(rows))
	for _, row := range rows {
		cookie, ok := DecryptRow(row, key)
		if !ok {
			counts.Undecryptable++
			continue
		}
		if !isLive(cookie, now, false) {
			counts.Expired++
			continue
		}
		cookies = append(cookies, cookie)
	}

	local, err := ReadLocalStorage(ctx, browser, profile)
	if err != nil {
		return StorageState{}, SeedCounts{}, fmt.Errorf("read local storage: %w", err)
	}
	session, err := ReadSessionStorage(ctx, browser, profile)
	if err != nil {
		return StorageState{}, SeedCounts{}, fmt.Errorf("read session storage: %w", err)
	}

	origins := map[string]*OriginStorage{}
	originFor := func(rawOrigin string) *OriginStorage {
		origin := canonicalOrigin(rawOrigin)
		storage, ok := origins[origin]
		if !ok {
			storage = &OriginStorage{Origin: origin}
			origins[origin] = storage
		}
		return storage
	}
	for origin, entries := range local {
		storage := originFor(origin)
		storage.LocalStorage = append(storage.LocalStorage, entries...)
	}
	for origin, entries := range session {
		storage := originFor(origin)
		storage.SessionStorage = append(storage.SessionStorage, entries...)
	}

	merged := make([]OriginStorage, 0, len(origins))
	for _, origin := range origins {
		sortEntries(origin.LocalStorage)
		sortEntries(origin.SessionStorage)
		merged = append(merged, *origin)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Origin < merged[j].Origin })

	return StorageState{Cookies: cookies, Origins: merged}, counts, nil
}
