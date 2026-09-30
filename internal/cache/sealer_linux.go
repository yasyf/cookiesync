//go:build linux

package cache

import (
	"context"
	"errors"

	"github.com/yasyf/cookiesync/internal/helper"
)

var errNoEnclave = errors.New("no Secure Enclave on linux")

// NoEnclave is the Linux Helper: a host with no Secure Enclave. Its cache-newkey
// always reports presence unavailable, so the cache opens in the MEMORY epoch
// and every Put's re-probe leaves it there — Degraded stays true and every
// entry keeps the DegradedTTL cap. Wrap, unwrap, and dropkey belong to an
// ENCLAVE epoch this helper never grants, so they fail closed.
type NoEnclave struct{}

// CacheNewkey reports presence unavailable: no Enclave key can be minted.
func (NoEnclave) CacheNewkey(context.Context, string) (helper.Result, error) {
	return helper.Result{Code: helper.CodePresenceUnavailable, Stderr: []byte(errNoEnclave.Error())}, nil
}

// CacheWrap fails closed: there is no Enclave key to wrap against.
func (NoEnclave) CacheWrap(context.Context, string, []byte) (helper.Result, error) {
	return helper.Result{}, errNoEnclave
}

// CacheUnwrap fails closed: there is no Enclave key to unwrap with.
func (NoEnclave) CacheUnwrap(context.Context, string, []byte) (helper.Result, error) {
	return helper.Result{}, errNoEnclave
}

// CacheDropkey fails closed: there is no Enclave key to drop.
func (NoEnclave) CacheDropkey(context.Context, string) (helper.Result, error) {
	return helper.Result{}, errNoEnclave
}
