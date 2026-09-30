package daemon

import (
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func requestHosts(urls []string) []cookie.Host {
	hosts := make([]cookie.Host, len(urls))
	for i, url := range urls {
		hosts[i] = cookie.NormalizeHost(url)
	}
	return hosts
}

func unixSeconds(now time.Time) float64 {
	return float64(now.UnixNano()) / 1e9
}

func everyHostNamed(records []importRecord, hosts []cookie.Host) bool {
	for _, h := range hosts {
		named := false
		for _, rec := range records {
			if rec.hosts[h] {
				named = true
				break
			}
		}
		if !named {
			return false
		}
	}
	return true
}

func (r importRecord) covers(hosts []cookie.Host) bool {
	for _, h := range hosts {
		if !r.hosts[h] {
			return false
		}
	}
	return true
}

func (r importRecord) namedHosts(hosts []cookie.Host) map[cookie.Host]bool {
	named := map[cookie.Host]bool{}
	for _, h := range hosts {
		if r.hosts[h] {
			named[h] = true
		}
	}
	return named
}

func (r importRecord) sendable(url string, now time.Time) []cookie.Cookie {
	host := cookie.NormalizeHost(url)
	nowSeconds := unixSeconds(now)
	var out []cookie.Cookie
	for _, c := range r.cookies {
		if cookie.Applies(c.HostKey, host) && cookie.Live(c, nowSeconds) {
			out = append(out, c)
		}
	}
	return out
}

func (r importRecord) originsFor(hosts map[cookie.Host]bool) []cookie.OriginStorage {
	var out []cookie.OriginStorage
	for _, o := range r.origins {
		if hosts[cookie.NormalizeHost(o.Origin)] {
			out = append(out, o)
		}
	}
	return out
}

func (r importRecord) seed(now time.Time) (cookie.StorageState, cookie.SeedCounts) {
	nowSeconds := unixSeconds(now)
	live := make([]cookie.Cookie, 0, len(r.cookies))
	for _, c := range r.cookies {
		if cookie.Live(c, nowSeconds) {
			live = append(live, c)
		}
	}
	counts := cookie.SeedCounts{Attempted: len(r.cookies), Expired: len(r.cookies) - len(live)}
	return cookie.StorageState{Cookies: live, Origins: r.origins}, counts
}

func (d *Daemon) importedCookies(browser, profile string, urls []string) (map[string]any, bool) {
	now := d.now()
	rec, ok := d.imports.live(importKey{browser: browser, profile: profile}, now)
	if !ok || !rec.covers(requestHosts(urls)) {
		return nil, false
	}
	sets := make([][]cookie.Cookie, 0, len(urls))
	for _, url := range urls {
		sets = append(sets, rec.sendable(url, now))
	}
	return cookiesPayload(cookie.Merge(sets...)), true
}

func (d *Daemon) importedCookiesUnion(urls []string) (map[string]any, bool) {
	now := d.now()
	records := d.imports.liveAll(now)
	hosts := requestHosts(urls)
	if !everyHostNamed(records, hosts) {
		return nil, false
	}
	sets := make([]cookie.RankedSet, 0, len(records))
	for _, rec := range records {
		var urlSets [][]cookie.Cookie
		for i, url := range urls {
			if rec.hosts[hosts[i]] {
				urlSets = append(urlSets, rec.sendable(url, now))
			}
		}
		if urlSets == nil {
			continue
		}
		sets = append(sets, cookie.RankedSet{Cookies: cookie.Merge(urlSets...), Local: true})
	}
	return cookiesPayload(cookie.MergeRanked(sets...)), true
}

func (d *Daemon) importedOrigins(browser, profile string, urls []string) (map[string]any, bool) {
	now := d.now()
	rec, ok := d.imports.live(importKey{browser: browser, profile: profile}, now)
	hosts := requestHosts(urls)
	if !ok || !rec.covers(hosts) {
		return nil, false
	}
	acc := map[string]*originAcc{}
	mergeOrigins(acc, rec.originsFor(rec.namedHosts(hosts)))
	return originsPayload(collectOrigins(acc)), true
}

func (d *Daemon) importedOriginsUnion(urls []string) (map[string]any, bool) {
	now := d.now()
	records := d.imports.liveAll(now)
	hosts := requestHosts(urls)
	if !everyHostNamed(records, hosts) {
		return nil, false
	}
	acc := map[string]*originAcc{}
	for _, rec := range records {
		mergeOrigins(acc, rec.originsFor(rec.namedHosts(hosts)))
	}
	return originsPayload(collectOrigins(acc)), true
}
