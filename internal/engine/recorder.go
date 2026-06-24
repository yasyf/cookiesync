package engine

import (
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// DigestRecorder is the in-memory anti-echo ledger: the last logical digest the sync
// layer applied to each endpoint. The converge pass records the digest of a merged
// set immediately before writing it, so a later fingerprint of the store (by the watch
// loop, a future cycle) matches the recorded digest and the self-induced write is
// recognized as the daemon's own echo rather than re-triggering a sync. It is safe for
// concurrent use; the watch daemon holds one for the process lifetime.
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
