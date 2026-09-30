//go:build linux

package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
)

func TestNoEnclaveNewkeyReportsPresenceUnavailable(t *testing.T) {
	result, err := NoEnclave{}.CacheNewkey(context.Background(), "label")
	if err != nil {
		t.Fatalf("CacheNewkey: %v", err)
	}
	if result.Code != helper.CodePresenceUnavailable {
		t.Fatalf("CacheNewkey code = %d, want %d", result.Code, helper.CodePresenceUnavailable)
	}
	if len(result.Stdout) != 0 {
		t.Fatalf("CacheNewkey stdout = %q, want empty", result.Stdout)
	}
}

func TestNoEnclaveEnclaveVerbsFailClosed(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func() (helper.Result, error)
	}{
		{"wrap", func() (helper.Result, error) { return NoEnclave{}.CacheWrap(ctx, "label", testKey()) }},
		{"unwrap", func() (helper.Result, error) { return NoEnclave{}.CacheUnwrap(ctx, "label", testKey()) }},
		{"dropkey", func() (helper.Result, error) { return NoEnclave{}.CacheDropkey(ctx, "label") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.call()
			if !errors.Is(err, errNoEnclave) {
				t.Fatalf("err = %v, want errNoEnclave", err)
			}
			if result.Code != 0 || len(result.Stdout) != 0 {
				t.Fatalf("result = %+v, want zero", result)
			}
		})
	}
}

func TestNoEnclaveCacheStaysInMemoryTier(t *testing.T) {
	ctx := context.Background()
	clk := newClock()
	c, err := open(ctx, NoEnclave{}, clk.now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !c.Degraded() {
		t.Fatal("a cache over NoEnclave must open degraded")
	}
	if kind := c.state.Load().kind; kind != stateMemory {
		t.Fatalf("open state = %d, want stateMemory", kind)
	}
	if c.keyLive {
		t.Fatal("NoEnclave must never provision an Enclave key")
	}

	for _, id := range []string{"vm:chrome:Default", "vm:chrome:Profile 1", "vm:chrome:Work"} {
		degraded, err := c.Put(ctx, id, testKey(), time.Hour)
		if err != nil {
			t.Fatalf("Put %s: %v", id, err)
		}
		if !degraded {
			t.Fatalf("Put %s published outside the MEMORY epoch", id)
		}
		if kind := c.state.Load().kind; kind != stateMemory {
			t.Fatalf("state after Put %s = %d, want stateMemory", id, kind)
		}
	}
	if !c.Degraded() {
		t.Fatal("Put re-probes must never heal a NoEnclave cache out of the degraded tier")
	}
	mustGet(t, c, "vm:chrome:Default", testKey())

	clk.advance(DegradedTTL - time.Second)
	mustGet(t, c, "vm:chrome:Default", testKey())
	clk.advance(2 * time.Second)
	if _, ok, err := c.Get(ctx, "vm:chrome:Default"); err != nil || ok {
		t.Fatalf("Get past DegradedTTL = ok %v err %v, want a miss: a one-hour TTL must be capped at %s", ok, err, DegradedTTL)
	}

	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.Put(ctx, "vm:chrome:Default", testKey(), time.Hour); !errors.Is(err, ErrClosed) {
		t.Fatalf("Put after Close = %v, want ErrClosed", err)
	}
}
