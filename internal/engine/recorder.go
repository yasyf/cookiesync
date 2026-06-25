package engine

import (
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// DigestRecorder is a standalone in-memory cookie.Recorder: the last logical digest
// the sync layer applied to each endpoint. With the watch loop now living in synckitd
// (which dedups a converge's own write by re-deriving the apply-stable fingerprint via
// `cookiesync list --json`), the resident helper has no in-process loop to echo to, so
// this is the recorder the engine records through — and the simple double the
// converge-layer tests record through. It is safe for concurrent use.
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
