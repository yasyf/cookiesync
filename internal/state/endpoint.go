// Package state loads and persists cookiesync's slice of the shared state.json: the
// self target, the cadence settings, the optional consent route, and the tracked
// browser endpoints as a convergent registry. It layers on the shared
// github.com/yasyf/synckit/hostregistry primitives — the same cross-process flock and
// the foreign-key-preserving raw writer — so cookiesync and the host registry share
// one file without clobbering each other's keys.
//
// The browser endpoints are a [cregistry.Registry] (a LWW-Element-Set CRDT) keyed by
// each endpoint's stable id "host:browser:profile", which is what lets an add or
// remove on one host propagate and converge across every host — the gap the per-host
// Python registry never closed. An add stamps added_at; a remove stamps removed_at as
// a tombstone, so a delete survives a sync with a host that never saw it.
package state

// EndpointID is an endpoint's stable identity, "host:browser:profile" — the key the
// convergent registry stores it under.
type EndpointID string

// EndpointMeta is the per-endpoint payload the convergent registry carries beyond the
// id: the host, browser, and profile that compose it. Carrying them in the registry
// value (not only the id) means a host that learns an endpoint through a registry
// merge has its full identity without parsing the id string. Every field is exported
// and JSON-tagged so the value's identity is captured in its encoding, which the CRDT
// equal-add tiebreak orders by.
type EndpointMeta struct {
	Host    string `json:"host"`
	Browser string `json:"browser"`
	Profile string `json:"profile"`
}

// Endpoint is one tracked browser profile on a host, the decoded form the sync engine
// works with. It is the registry id paired with its EndpointMeta.
type Endpoint struct {
	Host    string
	Browser string
	Profile string
}

// ID returns the endpoint's stable identity, "host:browser:profile".
func (e Endpoint) ID() EndpointID {
	return EndpointID(e.Host + ":" + e.Browser + ":" + e.Profile)
}

// Meta projects the endpoint into the registry payload.
func (e Endpoint) Meta() EndpointMeta {
	return EndpointMeta(e)
}

// endpointFromMeta rebuilds an Endpoint from a registry payload.
func endpointFromMeta(m EndpointMeta) Endpoint {
	return Endpoint(m)
}
