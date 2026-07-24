package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/testutil"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

// newTestStore builds a Store rooted at a temp config dir with a fixed clock, so
// registry stamps are deterministic. The isolation guard neutralizes any leaked
// config-dir override. It returns the store and the state.json path.
func newTestStore(t *testing.T, now time.Time) (*Store, string) {
	t.Helper()
	cfg := hostregistry.Config{Name: "cookiesync"}
	dir := testutil.IsolateHostConfig(t, cfg)
	store := NewWithClock(cfg, func() time.Time { return now })
	if err := store.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return store, filepath.Join(dir, "state.json")
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

// TestConsentRouteHardRoundTrip proves SetConsentRouteHard persists the hard-route flag
// and Load reads it back, independent of the routed target: it toggles true then false
// without disturbing consent_route_to.
func TestConsentRouteHardRoundTrip(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store, _ := newTestStore(t, now)

	if err := store.SetConsentRoute(ctx, "you@desktop"); err != nil {
		t.Fatalf("SetConsentRoute: %v", err)
	}
	if err := store.SetConsentRouteHard(ctx, true); err != nil {
		t.Fatalf("SetConsentRouteHard(true): %v", err)
	}

	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.ConsentRouteTo != "you@desktop" {
		t.Fatalf("consent_route_to = %q, want you@desktop", st.ConsentRouteTo)
	}
	if !st.ConsentRouteHard {
		t.Fatalf("consent_route_hard = false, want true after SetConsentRouteHard(true)")
	}

	// Downgrade: the flag clears but the routed target is untouched.
	if err := store.SetConsentRouteHard(ctx, false); err != nil {
		t.Fatalf("SetConsentRouteHard(false): %v", err)
	}
	st, err = store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.ConsentRouteHard {
		t.Fatalf("consent_route_hard = true, want false after SetConsentRouteHard(false)")
	}
	if st.ConsentRouteTo != "you@desktop" {
		t.Fatalf("consent_route_to = %q, want you@desktop (untouched by the hard toggle)", st.ConsentRouteTo)
	}
}

func TestExactEnvelopeOwnersDoNotClobberEachOther(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store, path := newTestStore(t, now)

	// Seed a host-registry slice into the same file first.
	cfg := store.cfg
	fact, err := hostregistry.NewSSHHostFact("you@desktop", "/usr/local/bin/synckitd", []string{"you@desktop"})
	if err != nil {
		t.Fatalf("new host fact: %v", err)
	}
	if err := cfg.RegisterHost(ctx, fact); err != nil {
		t.Fatalf("register host fact: %v", err)
	}
	if _, err := cfg.Update(ctx, func(g *hostregistry.Registry) error {
		g.Self = "me@laptop"
		return nil
	}); err != nil {
		t.Fatalf("seed host registry: %v", err)
	}

	ep := Endpoint{Host: "you@desktop", Browser: "arc", Profile: "Work"}
	if err := store.AddBrowser(ctx, "me@laptop", ep); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	raw := readStateFile(t, path)
	var host hostRegistryStateForTest
	if err := json.Unmarshal(raw["host_registry"], &host); err != nil {
		t.Fatalf("parse host_registry: %v", err)
	}
	if host.Self != "me@laptop" || len(host.Hosts) != 1 || host.Hosts[0].Identity != "you@desktop" {
		t.Fatalf("host_registry = %+v", host)
	}
	var persisted stateJSON
	if err := json.Unmarshal(raw[stateNamespace], &persisted); err != nil {
		t.Fatalf("parse cookiesync envelope: %v", err)
	}
	if _, ok := persisted.Browsers[string(ep.ID())]; !ok {
		t.Fatalf("cookiesync envelope missing browser")
	}
}

type hostRegistryStateForTest struct {
	Self  string                     `json:"self"`
	Hosts []hostregistry.SSHHostFact `json:"hosts"`
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
		AuthTTL:       "1h",
	}
	if got != want {
		t.Fatalf("default settings JSON = %+v, want %+v", got, want)
	}
}

func TestStateRejectsForeignTopLevelKeysWithoutEnvelope(t *testing.T) {
	store, path := newTestStore(t, time.Unix(1_700_000_000, 0))
	body := `{"another_owner":{"schema_version":99}}`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed state file: %v", err)
	}

	if _, err := store.Load(context.Background()); !errors.Is(err, hostregistry.ErrStateSchema) {
		t.Fatalf("Load foreign state = %v, want ErrStateSchema", err)
	}
}

func TestStateRejectsWrongOrExtendedV1Schema(t *testing.T) {
	for _, mutate := range []func(map[string]json.RawMessage){
		func(raw map[string]json.RawMessage) {
			var schema map[string]any
			_ = json.Unmarshal(raw["schema"], &schema)
			schema["version"] = 2
			raw["schema"], _ = json.Marshal(schema)
		},
		func(raw map[string]json.RawMessage) {
			var product map[string]any
			_ = json.Unmarshal(raw[stateNamespace], &product)
			product["extra"] = true
			raw[stateNamespace], _ = json.Marshal(product)
		},
		func(raw map[string]json.RawMessage) { raw["foreign"] = json.RawMessage(`{}`) },
	} {
		store, path := newTestStore(t, time.Unix(1_700_000_000, 0))
		raw := readStateFile(t, path)
		mutate(raw)
		body, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(context.Background()); !errors.Is(err, hostregistry.ErrStateSchema) {
			t.Fatalf("Load incompatible state = %v, want ErrStateSchema", err)
		}
	}
}

// TestBaselinesRoundTrip proves the rowcount ledger persists through the row_baselines
// key and reads back identically via both Baselines and Load, coexisting with the
// other state keys.
func TestBaselinesRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, time.Unix(1_700_000_000, 0))

	ep := Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, "me@laptop", ep); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	want := map[string]Baseline{
		"me@laptop:chrome:Default": {Rows: 9000},
		"me@laptop:arc:Default":    {Rows: 1200, Quarantined: true, QuarantinedRows: 12},
	}
	if err := store.SaveBaselinesUnlocked(ctx, want); err != nil {
		t.Fatalf("SaveBaselinesUnlocked: %v", err)
	}

	got, err := store.Baselines(ctx)
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Baselines() = %+v, want %+v", got, want)
	}
	for id, baseline := range want {
		if got[id] != baseline {
			t.Fatalf("Baselines()[%s] = %+v, want %+v", id, got[id], baseline)
		}
	}

	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Baselines["me@laptop:arc:Default"] != want["me@laptop:arc:Default"] {
		t.Fatalf("Load().Baselines = %+v, want %+v", st.Baselines, want)
	}
	if _, ok := st.Browsers[string(ep.ID())]; !ok {
		t.Fatalf("browsers key clobbered by the baselines write")
	}
	raw := readStateFile(t, path)
	var persisted stateJSON
	if err := json.Unmarshal(raw[stateNamespace], &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Baselines["me@laptop:arc:Default"] != want["me@laptop:arc:Default"] {
		t.Fatalf("persisted row_baselines = %+v, want %+v", persisted.Baselines, want)
	}
}

// TestBaselinesAbsentKeyIsEmpty proves a state.json without the row_baselines key
// yields an empty, non-nil ledger.
func TestBaselinesAbsentKeyIsEmpty(t *testing.T) {
	store, _ := newTestStore(t, time.Unix(1_700_000_000, 0))
	got, err := store.Baselines(context.Background())
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("Baselines() = %#v, want empty non-nil map", got)
	}
}
