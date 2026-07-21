package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

const (
	keyState = "cookiesync"
	// SchemaVersion is the only cookiesync state epoch this binary accepts.
	SchemaVersion = 1
)

// ErrSchemaMismatch means the cookiesync envelope is not exact schema v1.
var ErrSchemaMismatch = errors.New("cookiesync state schema mismatch; manually recreate cookiesync state in a fresh schema_version 1 envelope")

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

type stateJSON struct {
	SchemaVersion    uint64                           `json:"schema_version"`
	SelfTarget       string                           `json:"self_target"`
	Settings         settingsJSON                     `json:"settings"`
	ConsentRouteTo   string                           `json:"consent_route_to"`
	ConsentRouteHard bool                             `json:"consent_route_hard"`
	Browsers         cregistry.Registry[EndpointMeta] `json:"browsers"`
	Baselines        map[string]Baseline              `json:"row_baselines"`
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
	st, err := stateFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return st.Browsers, nil
}

// SaveRegistryUnlocked persists reg back into the browsers key of state.json,
// preserving every other key, WITHOUT acquiring the flock. It is the
// [converge.Driver] write side: the converge orchestration already holds the
// (non-reentrant) flock around the whole pass, so re-acquiring it here would
// self-deadlock. Use SaveRegistry for the standalone, lock-acquiring write.
func (s *Store) SaveRegistryUnlocked(_ context.Context, reg cregistry.Registry[EndpointMeta]) error {
	return s.cfg.UpdateRawUnlocked(func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Browsers = reg
		return putState(raw, st)
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
	st, err := stateFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return st.Baselines, nil
}

// SaveBaselinesUnlocked persists the rowcount ledger into the row_baselines key of
// state.json, preserving every other key, WITHOUT acquiring the flock — the converge
// pass writing it already holds the (non-reentrant) lock.
func (s *Store) SaveBaselinesUnlocked(_ context.Context, baselines map[string]Baseline) error {
	return s.cfg.UpdateRawUnlocked(func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Baselines = baselines
		return putState(raw, st)
	})
}

// SaveRegistry persists reg into the browsers key under the shared flock. For
// standalone callers; the converge pass uses SaveRegistryUnlocked because it already
// holds the lock.
func (s *Store) SaveRegistry(ctx context.Context, reg cregistry.Registry[EndpointMeta]) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Browsers = reg
		return putState(raw, st)
	})
}

// AddBrowser admits endpoint into the convergent registry, stamping the add at the
// store's clock so the mutation propagates and wins over an older view, then sets
// self_target. A re-add of a previously removed endpoint is admitted because the new
// stamp is strictly later than its tombstone.
func (s *Store) AddBrowser(ctx context.Context, selfTarget string, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Browsers.Add(string(endpoint.ID()), endpoint.Meta(), at)
		st.SelfTarget = selfTarget
		return putState(raw, st)
	})
}

// RemoveBrowser tombstones endpoint in the convergent registry, stamping the removal
// at the store's clock so the delete propagates and survives a sync with a host that
// never saw it.
func (s *Store) RemoveBrowser(ctx context.Context, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.Browsers.Remove(string(endpoint.ID()), at)
		return putState(raw, st)
	})
}

// SetConsentRoute records target as the host the consent gate routes user-presence
// checks to first.
func (s *Store) SetConsentRoute(ctx context.Context, target string) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.ConsentRouteTo = target
		return putState(raw, st)
	})
}

// SetConsentRouteHard records whether the consent gate must route to the configured
// target even when this host looks locally attended.
func (s *Store) SetConsentRouteHard(ctx context.Context, hard bool) error {
	return s.cfg.UpdateRaw(ctx, func(raw map[string]json.RawMessage) error {
		st, err := stateFromRaw(raw)
		if err != nil {
			return err
		}
		st.ConsentRouteHard = hard
		return putState(raw, st)
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
		return putState(raw, st)
	})
}

// stateFromRaw decodes only the exact v1 cookiesync envelope. An absent envelope
// is fresh state; every other top-level key belongs to another state owner.
func stateFromRaw(raw map[string]json.RawMessage) (*State, error) {
	encoded, found := raw[keyState]
	if !found {
		return defaultState(), nil
	}
	var persisted stateJSON
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return nil, fmt.Errorf("%w: decode v1 envelope: %w", ErrSchemaMismatch, err)
	}
	if persisted.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: state=%d binary=%d", ErrSchemaMismatch, persisted.SchemaVersion, SchemaVersion)
	}
	if persisted.Browsers == nil || persisted.Baselines == nil {
		return nil, fmt.Errorf("%w: v1 browsers and row_baselines must be objects", ErrSchemaMismatch)
	}
	settings, err := settingsFromJSON(persisted.Settings)
	if err != nil {
		return nil, fmt.Errorf("%w: parse settings: %w", ErrSchemaMismatch, err)
	}
	return &State{
		SelfTarget: persisted.SelfTarget, Settings: settings,
		ConsentRouteTo: persisted.ConsentRouteTo, ConsentRouteHard: persisted.ConsentRouteHard,
		Browsers: persisted.Browsers, Baselines: persisted.Baselines,
	}, nil
}

func defaultState() *State {
	return &State{
		Settings: DefaultSettings(), Browsers: cregistry.New[EndpointMeta](),
		Baselines: map[string]Baseline{},
	}
}

func putState(raw map[string]json.RawMessage, st *State) error {
	if st.Browsers == nil || st.Baselines == nil {
		return errors.New("encode cookiesync state: browsers and baselines must be non-nil")
	}
	encoded, err := json.Marshal(stateJSON{
		SchemaVersion: SchemaVersion, SelfTarget: st.SelfTarget, Settings: st.Settings.toJSON(),
		ConsentRouteTo: st.ConsentRouteTo, ConsentRouteHard: st.ConsentRouteHard,
		Browsers: st.Browsers, Baselines: st.Baselines,
	})
	if err != nil {
		return fmt.Errorf("encode cookiesync state: %w", err)
	}
	raw[keyState] = encoded
	return nil
}
