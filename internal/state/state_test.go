package state

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

// newTestStore builds a Store rooted at a temp XDG config dir with a fixed clock, so
// registry stamps are deterministic. It returns the store and the state.json path.
func newTestStore(t *testing.T, now time.Time) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := hostregistry.Config{Name: "cookiesync"}
	store := NewWithClock(cfg, func() time.Time { return now })
	return store, filepath.Join(dir, "cookiesync", "state.json")
}

func readStateFile(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a t.TempDir()-derived state file path in this test, not user-supplied.
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse state file: %v", err)
	}
	return raw
}

func TestAddBrowserStampsAndLoads(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store, _ := newTestStore(t, now)

	ep := Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, "me@laptop", ep); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.SelfTarget != "me@laptop" {
		t.Fatalf("self_target = %q, want me@laptop", st.SelfTarget)
	}
	entry, ok := st.Browsers[string(ep.ID())]
	if !ok {
		t.Fatalf("endpoint %s not in registry", ep.ID())
	}
	if !entry.Present() {
		t.Fatalf("added endpoint should be present")
	}
	if want := int64(now.UnixMicro()); int64(entry.Added) != want {
		t.Fatalf("added_at = %d, want %d", entry.Added, want)
	}
	if entry.Value != ep.Meta() {
		t.Fatalf("endpoint meta = %+v, want %+v", entry.Value, ep.Meta())
	}
	if eps := st.Endpoints(); len(eps) != 1 || eps[0] != ep {
		t.Fatalf("Endpoints() = %+v, want [%+v]", eps, ep)
	}
}

func TestRemoveBrowserTombstones(t *testing.T) {
	ctx := context.Background()
	add := time.Unix(1_700_000_000, 0)
	store, _ := newTestStore(t, add)
	ep := Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, "me@laptop", ep); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	// Advance the clock so the remove stamp is strictly newer than the add.
	store.now = func() time.Time { return add.Add(time.Minute) }
	if err := store.RemoveBrowser(ctx, ep); err != nil {
		t.Fatalf("RemoveBrowser: %v", err)
	}

	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entry, ok := st.Browsers[string(ep.ID())]
	if !ok {
		t.Fatalf("tombstoned endpoint must persist for convergence")
	}
	if entry.Present() {
		t.Fatalf("removed endpoint should be a tombstone, not present")
	}
	if len(st.Endpoints()) != 0 {
		t.Fatalf("Endpoints() should exclude tombstones, got %+v", st.Endpoints())
	}
}

// TestForeignKeyPreserve proves a write through the cookiesync store leaves the host
// registry's own keys (self, hosts) untouched, since both share the one state.json.
func TestForeignKeyPreserve(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store, path := newTestStore(t, now)

	// Seed a host-registry slice into the same file first.
	cfg := hostregistry.Config{Name: "cookiesync"}
	if _, err := cfg.Update(ctx, func(g *hostregistry.Registry) error {
		g.Self = "me@laptop"
		g.UpsertHost("you@desktop")
		return nil
	}); err != nil {
		t.Fatalf("seed host registry: %v", err)
	}

	ep := Endpoint{Host: "you@desktop", Browser: "arc", Profile: "Work"}
	if err := store.AddBrowser(ctx, "me@laptop", ep); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	raw := readStateFile(t, path)
	if _, ok := raw["hosts"]; !ok {
		t.Fatalf("host registry 'hosts' key clobbered by cookiesync write")
	}
	var hosts []string
	if err := json.Unmarshal(raw["hosts"], &hosts); err != nil {
		t.Fatalf("parse hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "you@desktop" {
		t.Fatalf("hosts = %+v, want [you@desktop]", hosts)
	}
	if _, ok := raw["browsers"]; !ok {
		t.Fatalf("cookiesync 'browsers' key missing")
	}
}

// TestSaveRegistryUnlockedNoSelfDeadlock proves the *Unlocked save path can be called
// from INSIDE a held WithLock without self-deadlocking on the non-reentrant flock —
// the exact path the converge orchestration uses. A naive SaveRegistry (which
// re-acquires the lock) would block here until ctx is done; the Unlocked path returns
// promptly.
func TestSaveRegistryUnlockedNoSelfDeadlock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store, _ := newTestStore(t, now)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reg := cregistry.New[EndpointMeta]()
	ep := Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	reg.Add(string(ep.ID()), ep.Meta(), 1)

	done := make(chan error, 1)
	go func() {
		done <- store.WithLock(ctx, func() error {
			// Inside the held lock: load and save through the unlocked paths.
			if _, err := store.LoadRegistry(ctx); err != nil {
				return err
			}
			return store.SaveRegistryUnlocked(ctx, reg)
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WithLock+SaveRegistryUnlocked: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("SaveRegistryUnlocked self-deadlocked inside WithLock")
	}

	st, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := st.Browsers[string(ep.ID())]; !ok {
		t.Fatalf("endpoint not persisted by SaveRegistryUnlocked")
	}
}

func TestSettingsDurationRoundTrip(t *testing.T) {
	cases := []struct {
		text string
		dur  time.Duration
	}{
		{"15m", 15 * time.Minute},
		{"5m", 5 * time.Minute},
		{"3s", 3 * time.Second},
		{"2m", 2 * time.Minute},
		{"1h", time.Hour},
		{"90s", 90 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			got, err := ParseDuration(tc.text)
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", tc.text, err)
			}
			if got != tc.dur {
				t.Fatalf("ParseDuration(%q) = %v, want %v", tc.text, got, tc.dur)
			}
		})
	}
	// FormatDuration picks the most compact unit.
	if got := FormatDuration(15 * time.Minute); got != "15m" {
		t.Fatalf("FormatDuration(15m) = %q, want 15m", got)
	}
	if got := FormatDuration(90 * time.Second); got != "90s" {
		t.Fatalf("FormatDuration(90s) = %q, want 90s", got)
	}
	if got := FormatDuration(time.Hour); got != "1h" {
		t.Fatalf("FormatDuration(1h) = %q, want 1h", got)
	}
}

// TestDefaultSettingsSerialize proves the default settings persist as the Go-style
// duration strings the Python on-disk form uses.
func TestDefaultSettingsSerialize(t *testing.T) {
	got := DefaultSettings().toJSON()
	want := settingsJSON{
		Interval:      "15m",
		IdleThreshold: "5m",
		WatchDebounce: "3s",
		OpTimeout:     "2m",
		AuthTTL:       "5m",
	}
	if got != want {
		t.Fatalf("default settings JSON = %+v, want %+v", got, want)
	}
}
