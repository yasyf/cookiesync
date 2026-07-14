package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

// JSON keys cookiesync owns in the shared state.json. The host-registry's own keys
// (self, hosts) are preserved untouched by every write here, since all writes go
// through the foreign-key-preserving hostregistry raw writer.
const (
	keySelfTarget       = "self_target"
	keyBrowsers         = "browsers"
	keySettings         = "settings"
	keyConsentRoute     = "consent_route_to"
	keyConsentRouteHard = "consent_route_hard"
	keyBaselines        = "row_baselines"
)

// Baseline is one endpoint's last-known-good extracted cookie rowcount and its
// mass-drop quarantine state, keyed by endpoint id in state.json. A collapse flips
// Quarantined and records the collapsed count for doctor.
type Baseline struct {
	Rows            int  `json:"rows"`
	Quarantined     bool `json:"quarantined,omitempty"`
	QuarantinedRows int  `json:"quarantined_rows,omitempty"`
}

// State is cookiesync's full on-disk configuration for this host: how peers reach it,
// the cadence settings, the optional consent route, and the convergent registry of
// tracked browser endpoints.
type State struct {
	SelfTarget       string
	Settings         Settings
	ConsentRouteTo   string
	ConsentRouteHard bool
	Browsers         cregistry.Registry[EndpointMeta]
	Baselines        map[string]Baseline
}

// Endpoints returns the present (non-tombstoned) tracked endpoints, decoded from the
// convergent registry.
func (s *State) Endpoints() []Endpoint {
	present := s.Browsers.Present()
	out := make([]Endpoint, 0, len(present))
	for _, entry := range present {
		out = append(out, endpointFromMeta(entry.Value))
	}
	return out
}

// Store is cookiesync's handle on the shared state.json: it owns the cookiesync keys
// and shares the host registry's cross-process flock and foreign-key-preserving raw
// writer, so cookiesync and the host registry never clobber each other's slice of the
// file. now is injectable so the registry's add/remove stamps are deterministic in
// tests.
type Store struct {
	cfg hostregistry.Config
	now func() time.Time
}

// New builds a Store over cfg, stamping registry mutations with the wall clock.
func New(cfg hostregistry.Config) *Store {
	return &Store{cfg: cfg, now: time.Now}
}

// NewWithClock builds a Store over cfg with an injected clock, for tests.
func NewWithClock(cfg hostregistry.Config, now func() time.Time) *Store {
	return &Store{cfg: cfg, now: now}
}

// WithLock runs fn while holding the shared reconcile flock — the same lock every
// cross-package writer of state.json acquires. A whole multi-step pass (such as a
// converge) wraps itself in this and then writes through the *Unlocked paths, since
// the flock is non-reentrant.
func (s *Store) WithLock(ctx context.Context, fn func() error) error {
	return s.cfg.WithLock(ctx, fn)
}

// readRaw reads state.json as raw JSON keys, returning an empty map when the file does
// not yet exist. It is a pure read — no lock, no write-back — so a read never churns
// the file or its key order.
func (s *Store) readRaw() (map[string]json.RawMessage, error) {
	path, err := s.cfg.Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the tool's own state.json under the fixed config dir, not user-supplied.
	if errors.Is(err, os.ErrNotExist) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return raw, nil
}

// Load reads the full cookiesync state, returning defaults for any key the file does
// not yet carry. It is a pure read.
func (s *Store) Load(_ context.Context) (*State, error) {
	raw, err := s.readRaw()
	if err != nil {
		return nil, err
	}
	return stateFromRaw(raw)
}

// LoadRegistry reads the convergent endpoint registry — including tombstones — out of
// state.json. It is the [converge.Driver] read side; a pure read that never acquires
// the flock, since the converge orchestration wraps the whole pass in WithLock.
func (s *Store) LoadRegistry(_ context.Context) (cregistry.Registry[EndpointMeta], error) {
	raw, err := s.readRaw()
	if err != nil {
		return nil, err
	}
	return browsersFromRaw(raw)
}

// SaveRegistryUnlocked persists reg back into the browsers key of state.json,
// preserving every other key, WITHOUT acquiring the flock. It is the
// [converge.Driver] write side: the converge orchestration already holds the
// (non-reentrant) flock around the whole pass, so re-acquiring it here would
// self-deadlock. Use SaveRegistry for the standalone, lock-acquiring write.
func (s *Store) SaveRegistryUnlocked(_ context.Context, reg cregistry.Registry[EndpointMeta]) error {
	return s.cfg.UpdateRawUnlocked(func(raw map[string]json.RawMessage) error {
		return putBrowsers(raw, reg)
	})
}

// Baselines reads the per-endpoint rowcount ledger out of state.json. A pure read that
// never acquires the flock (the converge pass consulting it already holds it); an
// absent key yields an empty, non-nil map.
func (s *Store) Baselines(_ context.Context) (map[string]Baseline, error) {
	raw, err := s.readRaw()
	if err != nil {
		return nil, err
	}
	return baselinesFromRaw(raw)
}

// SaveBaselinesUnlocked persists the rowcount ledger into the row_baselines key of
// state.json, preserving every other key, WITHOUT acquiring the flock — the converge
// pass writing it already holds the (non-reentrant) lock.
func (s *Store) SaveBaselinesUnlocked(_ context.Context, baselines map[string]Baseline) error {
	return s.cfg.UpdateRawUnlocked(func(raw map[string]json.RawMessage) error {
		return putBaselines(raw, baselines)
	})
}

// SaveRegistry persists reg into the browsers key under the shared flock. For
// standalone callers; the converge pass uses SaveRegistryUnlocked because it already
// holds the lock.
func (s *Store) SaveRegistry(ctx context.Context, reg cregistry.Registry[EndpointMeta]) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		return putBrowsers(raw, reg)
	})
}

// AddBrowser admits endpoint into the convergent registry, stamping the add at the
// store's clock so the mutation propagates and wins over an older view, then sets
// self_target. A re-add of a previously removed endpoint is admitted because the new
// stamp is strictly later than its tombstone.
func (s *Store) AddBrowser(ctx context.Context, selfTarget string, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		reg, err := browsersFromRaw(raw)
		if err != nil {
			return err
		}
		reg.Add(string(endpoint.ID()), endpoint.Meta(), at)
		if err := putBrowsers(raw, reg); err != nil {
			return err
		}
		return putString(raw, keySelfTarget, selfTarget)
	})
}

// RemoveBrowser tombstones endpoint in the convergent registry, stamping the removal
// at the store's clock so the delete propagates and survives a sync with a host that
// never saw it.
func (s *Store) RemoveBrowser(ctx context.Context, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		reg, err := browsersFromRaw(raw)
		if err != nil {
			return err
		}
		reg.Remove(string(endpoint.ID()), at)
		return putBrowsers(raw, reg)
	})
}

// SetConsentRoute records target as the host the consent gate routes user-presence
// checks to first.
func (s *Store) SetConsentRoute(ctx context.Context, target string) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		return putString(raw, keyConsentRoute, target)
	})
}

// SetConsentRouteHard records whether the consent gate must route to the configured
// target even when this host looks locally attended.
func (s *Store) SetConsentRouteHard(ctx context.Context, hard bool) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		return putBool(raw, keyConsentRouteHard, hard)
	})
}

// SetAuthTTL overrides the cached-key TTL setting, leaving the other cadence knobs
// untouched.
func (s *Store) SetAuthTTL(ctx context.Context, ttl time.Duration) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Settings.AuthTTL = ttl
		return putSettings(raw, st.Settings)
	})
}

// stateFromRaw decodes the cookiesync keys out of a raw state map, leaving defaults
// where a key is absent.
func stateFromRaw(raw map[string]json.RawMessage) (*State, error) {
	st := &State{Settings: DefaultSettings(), Browsers: cregistry.New[EndpointMeta]()}
	if v, ok := raw[keySelfTarget]; ok {
		if err := json.Unmarshal(v, &st.SelfTarget); err != nil {
			return nil, fmt.Errorf("parse self_target: %w", err)
		}
	}
	if v, ok := raw[keyConsentRoute]; ok {
		if err := json.Unmarshal(v, &st.ConsentRouteTo); err != nil {
			return nil, fmt.Errorf("parse consent_route_to: %w", err)
		}
	}
	if v, ok := raw[keyConsentRouteHard]; ok {
		if err := json.Unmarshal(v, &st.ConsentRouteHard); err != nil {
			return nil, fmt.Errorf("parse consent_route_hard: %w", err)
		}
	}
	if v, ok := raw[keySettings]; ok {
		var sj settingsJSON
		if err := json.Unmarshal(v, &sj); err != nil {
			return nil, fmt.Errorf("parse settings: %w", err)
		}
		settings, err := settingsFromJSON(sj)
		if err != nil {
			return nil, fmt.Errorf("parse settings: %w", err)
		}
		st.Settings = settings
	}
	reg, err := browsersFromRaw(raw)
	if err != nil {
		return nil, err
	}
	st.Browsers = reg
	baselines, err := baselinesFromRaw(raw)
	if err != nil {
		return nil, err
	}
	st.Baselines = baselines
	return st, nil
}

// baselinesFromRaw decodes the rowcount ledger out of the row_baselines key, returning
// an empty map when the key is absent.
func baselinesFromRaw(raw map[string]json.RawMessage) (map[string]Baseline, error) {
	baselines := map[string]Baseline{}
	v, ok := raw[keyBaselines]
	if !ok {
		return baselines, nil
	}
	if err := json.Unmarshal(v, &baselines); err != nil {
		return nil, fmt.Errorf("parse row_baselines: %w", err)
	}
	return baselines, nil
}

// browsersFromRaw decodes the convergent endpoint registry out of the browsers key,
// returning an empty registry when the key is absent.
func browsersFromRaw(raw map[string]json.RawMessage) (cregistry.Registry[EndpointMeta], error) {
	reg := cregistry.New[EndpointMeta]()
	v, ok := raw[keyBrowsers]
	if !ok {
		return reg, nil
	}
	if err := json.Unmarshal(v, &reg); err != nil {
		return nil, fmt.Errorf("parse browsers registry: %w", err)
	}
	if reg == nil {
		reg = cregistry.New[EndpointMeta]()
	}
	return reg, nil
}

func putBrowsers(raw map[string]json.RawMessage, reg cregistry.Registry[EndpointMeta]) error {
	encoded, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("encode browsers registry: %w", err)
	}
	raw[keyBrowsers] = encoded
	return nil
}

func putBaselines(raw map[string]json.RawMessage, baselines map[string]Baseline) error {
	encoded, err := json.Marshal(baselines)
	if err != nil {
		return fmt.Errorf("encode row_baselines: %w", err)
	}
	raw[keyBaselines] = encoded
	return nil
}

func putSettings(raw map[string]json.RawMessage, settings Settings) error {
	encoded, err := json.Marshal(settings.toJSON())
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}
	raw[keySettings] = encoded
	return nil
}

func putString(raw map[string]json.RawMessage, key, value string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	raw[key] = encoded
	return nil
}

func putBool(raw map[string]json.RawMessage, key string, value bool) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	raw[key] = encoded
	return nil
}
