package cookie

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// SeedState decrypts every cookie and all local/session storage in a profile for bridge seeding.
// It returns the full StorageState plus the number of undecryptable/skipped cookie rows (a caller may
// fail loud on a materially incomplete clone). key must already be released by the consent layer.
func SeedState(ctx context.Context, browser Browser, profile string, key AesKey) (state StorageState, skipped int, err error) {
	rows, err := Read(ctx, browser, profile)
	if err != nil {
		return StorageState{}, 0, fmt.Errorf("read cookies: %w", err)
	}

	now := float64(time.Now().UnixNano()) / 1e9
	cookies := make([]Cookie, 0, len(rows))
	for _, row := range rows {
		cookie, ok := DecryptRow(row, key)
		if !ok {
			skipped++
			continue
		}
		if isLive(cookie, now, false) {
			cookies = append(cookies, cookie)
		}
	}

	local, err := ReadLocalStorage(ctx, browser, profile)
	if err != nil {
		return StorageState{}, 0, fmt.Errorf("read local storage: %w", err)
	}
	session, err := ReadSessionStorage(ctx, browser, profile)
	if err != nil {
		return StorageState{}, 0, fmt.Errorf("read session storage: %w", err)
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

	return StorageState{Cookies: cookies, Origins: merged}, skipped, nil
}
