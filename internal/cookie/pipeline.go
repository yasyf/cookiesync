package cookie

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The extract/apply pipeline over a cookie store with an already-obtained key.
//
// Extract decrypts a host's cookies from the store: the consent gate is the
// caller's responsibility — key is passed in, never obtained here, so Extract is pure
// given its key. It reads the profile's rows, filters to the ones the browser would
// send to the host, decrypts each (skipping v20 app-bound and otherwise-undecryptable
// rows), drops expired cookies unless includeExpired, and — when self-decrypt yields
// nothing and fallback is set — runs the cross-browser get-cookie sweep instead. Apply
// re-encrypts a cookie set back into the store. This mirrors the Python pipeline.extract
// / pipeline.apply and backend.LocalBackend host-filter exactly.

// DecryptCounts tallies the rows Extract could not decrypt: v20 app-bound rows and
// rows that failed for any other reason. It is returned alongside the decrypted set
// so a caller can log why a host yielded fewer cookies than its store holds.
type DecryptCounts struct {
	V20    int
	Failed int
}

// cookieFromRow lifts a decrypted value and its row into a Cookie.
func cookieFromRow(row EncryptedRow, value string) Cookie {
	return Cookie{
		HostKey:              row.HostKey,
		Name:                 row.Name,
		Value:                value,
		Path:                 row.Path,
		ExpiresUTC:           row.ExpiresUTC,
		LastUpdateUTC:        row.LastUpdateUTC,
		CreationUTC:          row.CreationUTC,
		IsSecure:             row.IsSecure,
		IsHTTPOnly:           row.IsHTTPOnly,
		SameSite:             row.SameSite,
		SourceScheme:         row.SourceScheme,
		SourcePort:           row.SourcePort,
		TopFrameSiteKey:      row.TopFrameSiteKey,
		HasCrossSiteAncestor: row.HasCrossSiteAncestor,
	}
}

// DecryptRows decrypts rows read from one store with key. A row that fails on its
// own (v20 app-bound, wrong key, corrupt) is skipped and tallied; a condition that
// makes the store unreadable on this host — a v11 row with no keyring key
// (ErrV11KeyUnavailable) or an unsupported tag (ErrUnsupportedPrefix) — fails the
// whole call rather than dropping rows.
func DecryptRows(rows []EncryptedRow, key AesKey) ([]Cookie, DecryptCounts, error) {
	return hostCodec.decryptRows(rows, key)
}

func (c codec) decryptRows(rows []EncryptedRow, key AesKey) ([]Cookie, DecryptCounts, error) {
	var counts DecryptCounts
	cookies := make([]Cookie, 0, len(rows))
	for _, row := range rows {
		cookie, ok, err := c.decryptRow(row, key, &counts)
		if err != nil {
			return nil, DecryptCounts{}, err
		}
		if ok {
			cookies = append(cookies, cookie)
		}
	}
	return cookies, counts, nil
}

func (c codec) decryptRow(row EncryptedRow, key AesKey, counts *DecryptCounts) (Cookie, bool, error) {
	value, err := c.open(row.EncryptedValue, key, row.HostKey, row.metaVersion)
	switch {
	case err == nil:
		return cookieFromRow(row, value), true, nil
	case errors.Is(err, ErrV11KeyUnavailable), errors.Is(err, ErrUnsupportedPrefix):
		return Cookie{}, false, fmt.Errorf("decrypt cookie store: %w", err)
	case errors.Is(err, ErrV20):
		counts.V20++
	default:
		counts.Failed++
	}
	return Cookie{}, false, nil
}

// isLive reports whether a cookie should be kept: includeExpired keeps everything; a
// session cookie (no expiry) is always live; otherwise its expiry must not be in the
// past. now is Unix seconds, matching the Python expires >= now comparison.
func isLive(cookie Cookie, now float64, includeExpired bool) bool {
	if includeExpired {
		return true
	}
	expires, session := chromeMicrosToUnix(cookie.ExpiresUTC)
	if session {
		return true
	}
	return expires >= now
}

// Live reports whether cookie survives Extract's expiry filter at now (Unix seconds): a
// session cookie always does, a persistent one while its expiry is not in the past.
func Live(cookie Cookie, now float64) bool {
	return isLive(cookie, now, false)
}

// Syncable reports whether cookie is persistent and has not expired at now.
func Syncable(cookie Cookie, now float64) bool {
	expires, session := chromeMicrosToUnix(cookie.ExpiresUTC)
	return !session && expires >= now
}

// FilterSyncable returns the persistent cookies that have not expired at now.
func FilterSyncable(cookies []Cookie, now float64) []Cookie {
	filtered := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if Syncable(cookie, now) {
			filtered = append(filtered, cookie)
		}
	}
	return filtered
}

// Extract decrypts the cookies the browser would send to url's host from profile,
// using the already-obtained key. Rows are host-filtered, decrypted (v20 app-bound
// and otherwise-undecryptable rows skipped), and expired cookies dropped unless
// includeExpired. When self-decrypt yields nothing and fallback is set, the
// cross-browser get-cookie sweep runs instead. The consent gate is the caller's; key
// is never obtained here.
func Extract(
	ctx context.Context,
	url string,
	browser Browser,
	key AesKey,
	profile string,
	includeExpired bool,
	fallback bool,
) (StorageState, error) {
	return hostCodec.extract(ctx, url, browser, key, profile, includeExpired, fallback)
}

func (c codec) extract(
	ctx context.Context,
	url string,
	browser Browser,
	key AesKey,
	profile string,
	includeExpired bool,
	fallback bool,
) (StorageState, error) {
	host := NormalizeHost(url)
	rows, err := c.read(ctx, browser, profile)
	if err != nil {
		return StorageState{}, err
	}
	now := float64(time.Now().UnixNano()) / 1e9
	var counts DecryptCounts
	cookies := make([]Cookie, 0, len(rows))
	for _, row := range rows {
		if !Applies(row.HostKey, host) {
			continue
		}
		cookie, ok, err := c.decryptRow(row, key, &counts)
		if err != nil {
			return StorageState{}, err
		}
		if !ok {
			continue
		}
		if isLive(cookie, now, includeExpired) {
			cookies = append(cookies, cookie)
		}
	}
	if len(cookies) == 0 && fallback {
		fetched, fetchErr := FetchCookies(ctx, host)
		if fetchErr != nil {
			return StorageState{}, fetchErr
		}
		return StorageState{Cookies: fetched}, nil
	}
	return StorageState{Cookies: cookies}, nil
}

// Apply re-encrypts cookies into profile's live store with key, returning the number
// of rows written (-1 on a soft-busy locked store, per Write).
func Apply(ctx context.Context, cookies []Cookie, browser Browser, profile string, key AesKey) (int, error) {
	return hostCodec.apply(ctx, cookies, browser, profile, key)
}

func (c codec) apply(ctx context.Context, cookies []Cookie, browser Browser, profile string, key AesKey) (int, error) {
	return c.write(ctx, browser, profile, cookies, key)
}
