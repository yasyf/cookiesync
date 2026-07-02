package engine

import "sync"

// keyedLocks is a lazily-populated mutex per key; the zero value is ready to use.
// lock blocks until the key's mutex is held and returns it for the caller to Unlock;
// distinct keys never contend.
type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedLocks) lock(key string) *sync.Mutex {
	k.mu.Lock()
	m, ok := k.locks[key]
	if !ok {
		if k.locks == nil {
			k.locks = map[string]*sync.Mutex{}
		}
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m
}
