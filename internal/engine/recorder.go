package engine

import (
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// DigestRecorder is a standalone in-memory cookie.Recorder: the last logical digest
// the sync layer applied to each endpoint, with no watch engine behind it. The
// resident daemon seeds the watch engine's own ledger instead (watch.EngineRecorder),
// so this is the recorder for a converge with no resident watch loop to echo to — and
// the simple double the converge-layer tests record through. It is safe for concurrent
// use.
type DigestRecorder struct {
	mu      sync.Mutex
	digests map[string]cookie.Digest
}

// NewDigestRecorder returns an empty recorder.
func NewDigestRecorder() *DigestRecorder {
	return &DigestRecorder{digests: make(map[string]cookie.Digest)}
}

// RecordApplied records digest as endpointID's applied state.
func (r *DigestRecorder) RecordApplied(endpointID string, digest cookie.Digest) {
	r.mu.Lock()
	r.digests[endpointID] = digest
	r.mu.Unlock()
}

// Applied returns the last digest recorded for endpointID, if any.
func (r *DigestRecorder) Applied(endpointID string) (cookie.Digest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.digests[endpointID]
	return d, ok
}
