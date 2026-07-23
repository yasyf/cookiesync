package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

const (
	stateIdentity    = "cookie-sync-state-v1"
	stateNamespace   = "cookie_sync"
	stateDeclaration = "schema:{identity:string,version:uint64,fingerprint:string};host_registry:{self:string,hosts:array<string>,addrs:map<string,array<string>>};cookie_sync:{self_target:string,settings:{interval:duration,idle_threshold:duration,watch_debounce:duration,auth_ttl:duration},consent_route_to:string,consent_route_hard:bool,browsers:map<string,{added_at:int64,removed_at:int64,value:{host:string,browser:string,profile:string}}>,row_baselines:map<string,{rows:int,quarantined:bool,quarantined_rows:int}>}"
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

type stateJSON struct {
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

// Store is cookiesync's handle on the exact state.json envelope. It owns the
// cookie_sync payload and shares the host registry's cross-process flock, so
// mutations cannot clobber the declared host_registry payload. now is injectable
// so registry stamps are deterministic in tests.
type Store struct {
	cfg hostregistry.Config
	now func() time.Time
}

// New builds a Store over cfg, stamping registry mutations with the wall clock.
func New(cfg hostregistry.Config) *Store {
	return &Store{cfg: cfg.WithStateContract(stateContract()), now: time.Now}
}

// NewWithClock builds a Store over cfg with an injected clock, for tests.
func NewWithClock(cfg hostregistry.Config, now func() time.Time) *Store {
	return &Store{cfg: cfg.WithStateContract(stateContract()), now: now}
}

func stateContract() hostregistry.StateContract {
	return hostregistry.StateContract{
		Identity: stateIdentity, Fingerprint: hostregistry.SchemaFingerprint(stateIdentity, stateDeclaration),
		ProductNamespace: stateNamespace, InitialProduct: mustEncodeState(defaultState()), ValidateProduct: validateProduct,
	}
}

// Initialize creates a fresh complete v1 envelope when none exists.
func (s *Store) Initialize(ctx context.Context) error { return s.cfg.InitializeState(ctx) }

// WithLock runs fn while holding the shared reconcile flock — the same lock every
// cross-package writer of state.json acquires. A whole multi-step pass (such as a
// converge) wraps itself in this and then writes through the *Unlocked paths, since
// the flock is non-reentrant.
func (s *Store) WithLock(ctx context.Context, fn func() error) error {
	return s.cfg.WithLock(ctx, fn)
}

// Load reads the full exact schema v1 cookie-sync state.
func (s *Store) Load(_ context.Context) (*State, error) {
	raw, err := s.cfg.LoadProduct()
	if err != nil {
		return nil, err
	}
	return stateFromProduct(raw)
}

// LoadRegistry reads the convergent endpoint registry — including tombstones — out of
// state.json. It is the [converge.Driver] read side; a pure read that never acquires
// the flock, since the converge orchestration wraps the whole pass in WithLock.
func (s *Store) LoadRegistry(ctx context.Context) (cregistry.Registry[EndpointMeta], error) {
	st, err := s.Load(ctx)
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
	return s.cfg.UpdateProductUnlocked(func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Browsers = reg
		return encodeState(st)
	})
}

// Baselines reads the per-endpoint rowcount ledger out of state.json. A pure read that
// never acquires the flock (the converge pass consulting it already holds it); an
// absent key yields an empty, non-nil map.
func (s *Store) Baselines(ctx context.Context) (map[string]Baseline, error) {
	st, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	return st.Baselines, nil
}

// SaveBaselinesUnlocked persists the rowcount ledger into the row_baselines key of
// state.json, preserving every other key, WITHOUT acquiring the flock — the converge
// pass writing it already holds the (non-reentrant) lock.
func (s *Store) SaveBaselinesUnlocked(_ context.Context, baselines map[string]Baseline) error {
	return s.cfg.UpdateProductUnlocked(func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Baselines = baselines
		return encodeState(st)
	})
}

// SaveRegistry persists reg into the browsers key under the shared flock. For
// standalone callers; the converge pass uses SaveRegistryUnlocked because it already
// holds the lock.
func (s *Store) SaveRegistry(ctx context.Context, reg cregistry.Registry[EndpointMeta]) error {
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Browsers = reg
		return encodeState(st)
	})
}

// AddBrowser admits endpoint into the convergent registry, stamping the add at the
// store's clock so the mutation propagates and wins over an older view, then sets
// self_target. A re-add of a previously removed endpoint is admitted because the new
// stamp is strictly later than its tombstone.
func (s *Store) AddBrowser(ctx context.Context, selfTarget string, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Browsers.Add(string(endpoint.ID()), endpoint.Meta(), at)
		st.SelfTarget = selfTarget
		return encodeState(st)
	})
}

// RemoveBrowser tombstones endpoint in the convergent registry, stamping the removal
// at the store's clock so the delete propagates and survives a sync with a host that
// never saw it.
func (s *Store) RemoveBrowser(ctx context.Context, endpoint Endpoint) error {
	at := cregistry.UnixMicros(s.now())
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Browsers.Remove(string(endpoint.ID()), at)
		return encodeState(st)
	})
}

// SetConsentRoute records target as the host the consent gate routes user-presence
// checks to first.
func (s *Store) SetConsentRoute(ctx context.Context, target string) error {
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.ConsentRouteTo = target
		return encodeState(st)
	})
}

// SetConsentRouteHard records whether the consent gate must route to the configured
// target even when this host looks locally attended.
func (s *Store) SetConsentRouteHard(ctx context.Context, hard bool) error {
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.ConsentRouteHard = hard
		return encodeState(st)
	})
}

// SetAuthTTL overrides the cached-key TTL setting, leaving the other cadence knobs
// untouched.
func (s *Store) SetAuthTTL(ctx context.Context, ttl time.Duration) error {
	return s.cfg.UpdateProduct(ctx, func(raw json.RawMessage) (json.RawMessage, error) {
		st, err := stateFromProduct(raw)
		if err != nil {
			return nil, err
		}
		st.Settings.AuthTTL = ttl
		return encodeState(st)
	})
}

func stateFromProduct(encoded json.RawMessage) (*State, error) {
	var persisted stateJSON
	if err := hostregistry.DecodeExactJSON(encoded, &persisted); err != nil {
		return nil, fmt.Errorf("decode cookie_sync: %w", err)
	}
	if persisted.Browsers == nil || persisted.Baselines == nil {
		return nil, errors.New("cookie_sync browsers and row_baselines must be objects")
	}
	settings, err := settingsFromJSON(persisted.Settings)
	if err != nil {
		return nil, fmt.Errorf("parse cookie_sync settings: %w", err)
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

func encodeState(st *State) (json.RawMessage, error) {
	if st.Browsers == nil || st.Baselines == nil {
		return nil, errors.New("encode cookie-sync state: browsers and baselines must be non-nil")
	}
	encoded, err := json.Marshal(stateJSON{
		SelfTarget: st.SelfTarget, Settings: st.Settings.toJSON(),
		ConsentRouteTo: st.ConsentRouteTo, ConsentRouteHard: st.ConsentRouteHard,
		Browsers: st.Browsers, Baselines: st.Baselines,
	})
	if err != nil {
		return nil, fmt.Errorf("encode cookie-sync state: %w", err)
	}
	return encoded, nil
}

func validateProduct(raw json.RawMessage) error { _, err := stateFromProduct(raw); return err }

func mustEncodeState(st *State) json.RawMessage {
	raw, err := encodeState(st)
	if err != nil {
		panic(err)
	}
	return raw
}
