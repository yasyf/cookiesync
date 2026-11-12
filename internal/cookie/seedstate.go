package cookie

import (
	"context"
	"fmt"
	"time"
)

// SeedCounts tallies why each cookie row a seed considered was kept or dropped:
// Attempted is every row a browser would send to a requested host, Undecryptable
// the rows DecryptRow could not decrypt, Expired the decrypted rows isLive dropped.
// The kept cookies (Attempted - Undecryptable - Expired) travel in the StorageState.
type SeedCounts struct {
	Attempted     int
	Undecryptable int
	Expired       int
}

// SeedState decrypts the cookies a browser would send to urls' hosts, plus those
// hosts' local and session storage, from a profile for bridge seeding. It returns
// the StorageState plus a per-cause count of the cookie rows it dropped (a caller
// may fail loud on a materially incomplete clone). key must already be released by
// the consent layer.
func SeedState(ctx context.Context, urls []string, browser Browser, profile string, key AesKey) (StorageState, SeedCounts, error) {
	return hostCodec.seedState(ctx, urls, browser, profile, key)
}

func (c codec) seedState(ctx context.Context, urls []string, browser Browser, profile string, key AesKey) (state StorageState, counts SeedCounts, err error) {
	rows, err := c.read(ctx, browser, profile)
	if err != nil {
		return StorageState{}, SeedCounts{}, fmt.Errorf("read cookies: %w", err)
	}

	hosts := make([]Host, len(urls))
	for i, url := range urls {
		hosts[i] = NormalizeHost(url)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	var cookies []Cookie
	var failed DecryptCounts
	for _, row := range rows {
		if !AppliesAny(row.HostKey, hosts) {
			continue
		}
		counts.Attempted++
		cookie, ok, err := c.decryptRow(row, key, &failed)
		if err != nil {
			return StorageState{}, SeedCounts{}, fmt.Errorf("decrypt cookies: %w", err)
		}
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

	origins, err := ExtractWebStorage(ctx, urls, browser, profile)
	if err != nil {
		return StorageState{}, SeedCounts{}, fmt.Errorf("read web storage: %w", err)
	}
	return StorageState{Cookies: cookies, Origins: origins}, counts, nil
}

// CountLive counts, for each of hosts, the unexpired cookie rows in profile a
// browser would send to it. It decrypts no value.
func CountLive(ctx context.Context, browser Browser, profile string, hosts []Host) ([]int, error) {
	return hostCodec.countLive(ctx, browser, profile, hosts)
}

func (c codec) countLive(ctx context.Context, browser Browser, profile string, hosts []Host) ([]int, error) {
	rows, err := c.read(ctx, browser, profile)
	if err != nil {
		return nil, fmt.Errorf("read cookies: %w", err)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	counts := make([]int, len(hosts))
	for _, row := range rows {
		if !unexpired(row.ExpiresUTC, now) {
			continue
		}
		for i, host := range hosts {
			if Applies(row.HostKey, host) {
				counts[i]++
			}
		}
	}
	return counts, nil
}
