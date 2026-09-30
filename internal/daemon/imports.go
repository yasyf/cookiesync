package daemon

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

const (
	importMinTTL     = time.Second
	importMaxTTL     = 24 * time.Hour
	importMaxRecords = 16
)

type importKey struct {
	browser string
	profile string
}

type importRecord struct {
	hosts     map[cookie.Host]bool
	cookies   []cookie.Cookie
	origins   []cookie.OriginStorage
	expiresAt time.Time
}

type importStore struct {
	mu      sync.Mutex
	records map[importKey]importRecord
}

func (r importRecord) hostList() []string {
	hosts := make([]string, 0, len(r.hosts))
	for host := range r.hosts {
		hosts = append(hosts, string(host))
	}
	slices.Sort(hosts)
	return hosts
}

func (s *importStore) put(key importKey, rec importRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = rec
}

func (s *importStore) hold(key importKey, rec importRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, replacing := s.records[key]; !replacing && len(s.records) >= importMaxRecords {
		return fmt.Errorf("import refused: %d records already held", importMaxRecords)
	}
	s.records[key] = rec
	return nil
}

func (s *importStore) live(key importKey, now time.Time) (importRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[key]
	if !ok {
		return importRecord{}, false
	}
	if !rec.expiresAt.After(now) {
		delete(s.records, key)
		return importRecord{}, false
	}
	return rec, true
}

func (s *importStore) liveAll(now time.Time) []importRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]importKey, 0, len(s.records))
	for key, rec := range s.records {
		if !rec.expiresAt.After(now) {
			delete(s.records, key)
			continue
		}
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b importKey) int {
		return cmp.Or(cmp.Compare(a.browser, b.browser), cmp.Compare(a.profile, b.profile))
	})
	records := make([]importRecord, len(keys))
	for i, key := range keys {
		records[i] = s.records[key]
	}
	return records
}

func (s *importStore) purge(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, rec := range s.records {
		if !rec.expiresAt.After(now) {
			delete(s.records, key)
		}
	}
}

func newImportStore() *importStore {
	return &importStore{records: map[importKey]importRecord{}}
}

func newImportRecord(hosts []string, parsed cookie.StorageState, expiresAt time.Time) (importRecord, error) {
	named := make(map[cookie.Host]bool, len(hosts))
	for _, raw := range hosts {
		if !bareOrigin(raw) {
			return importRecord{}, fmt.Errorf("import host %q must be a bare host or an origin", raw)
		}
		named[cookie.NormalizeHost(raw)] = true
	}
	for _, c := range parsed.Cookies {
		if !sentToNamedHost(c.HostKey, named) {
			return importRecord{}, fmt.Errorf("import refused: cookie %q for %s is sent to none of the named hosts", c.Name, c.HostKey)
		}
	}
	for _, o := range parsed.Origins {
		if !bareOrigin(o.Origin) {
			return importRecord{}, fmt.Errorf("import refused: origin %s is not a bare origin", o.Origin)
		}
		if !named[cookie.NormalizeHost(o.Origin)] {
			return importRecord{}, fmt.Errorf("import refused: origin %s is not a named host", o.Origin)
		}
	}
	return importRecord{hosts: named, cookies: parsed.Cookies, origins: parsed.Origins, expiresAt: expiresAt}, nil
}

func bareOrigin(raw string) bool {
	text := strings.TrimSpace(raw)
	if !strings.Contains(text, "://") {
		text = "https://" + text
	}
	u, err := url.Parse(text)
	if err != nil || strings.ContainsAny(text, `\?#`) {
		return false
	}
	return u.User == nil && (u.Path == "" || u.Path == "/") && u.Hostname() != ""
}

func sentToNamedHost(hostKey cookie.HostKey, named map[cookie.Host]bool) bool {
	for host := range named {
		if cookie.Applies(hostKey, host) {
			return true
		}
	}
	return false
}

// ImportTTL parses an import --ttl with the auth --ttl grammar and refuses a lifetime
// outside 1s..24h.
func ImportTTL(text string) (time.Duration, error) {
	ttl, err := state.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("import ttl: %w", err)
	}
	if ttl < importMinTTL || ttl > importMaxTTL {
		return 0, fmt.Errorf("import ttl %s is outside 1s..24h", text)
	}
	return ttl, nil
}
