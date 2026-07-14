// Package daemon is the resident cookiesync daemon: the unix-socket RPC server,
// the method handlers, and the wire shapes they freeze. It listens on
// paths.SockPath via the shared synckit/rpc transport (the frozen
// {method, params} -> {ok, result, error} wire) and dispatches the bimodal
// method set.
//
// The method set splits in two. Peer methods carry an origin and are how peers
// drive this host over ssh: sync converges the local union (suppressing the
// origin), reconcile runs a full pass, extract returns this host's decrypted
// cookies as wire records (priming auth if the key is cold), apply ingests a
// merged wire set, and whoami reports this host's console session. Local
// methods are terminal and carry no origin — what the CLI on this box invokes:
// prime_auth obtains the Safe Storage keys and caches them; get_cookies renders
// one or more urls' cookies, merged into one set, behind the same gate;
// auth_status reports cache warmth and Secure-Enclave degradation;
// request_consent shows the Touch ID prompt for the named browser to the person
// at this machine and echoes the requester's nonce + endpoint to bind the
// approval — the key never crosses hosts.
//
// Everything key-shaped — the grants store, the key cache, the prompt gate, the
// release singleflight, and every release path — lives in the internal/auth
// Broker; the handlers here hold no cache or grants reference and only render
// wire shapes from the broker's typed results. Every collaborator is injected
// behind a seam, so the whole dispatcher runs in unit tests against fakes
// without a real macOS API, ssh, or cookie store.
package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/debug"
	"github.com/yasyf/synckit/presence"
	synckit "github.com/yasyf/synckit/rpc"
	"github.com/yasyf/synckit/syncservice"
)

// consentReason is the default Touch ID prompt reason for a prime_auth with no
// caller-supplied reason — the frozen wording the Python daemon uses.
const consentReason = "sync them across your Macs"

// defaultProfile is the profile a method assumes when the request omits one,
// matching the Python DEFAULT_PROFILE.
const defaultProfile = "Default"

// Cache is the key-cache slice the daemon threads into the auth broker.
type Cache = auth.Cache

// StateLoader loads the cookiesync state — the read seam the handlers resolve
// endpoints and settings through; injected so handlers run against a fixture.
type StateLoader = auth.StateLoader

// Probe reads this host's console GUI session; injected so the session logic
// runs in tests against synthetic snapshots.
type Probe = auth.Probe

// SessionSnapshot is a point-in-time read of this host's console GUI session.
type SessionSnapshot = presence.SessionSnapshot

// Daemon holds every collaborator behind an injected seam so the dispatcher
// runs in unit tests against fakes. In production it is built by Build with the
// real consent gate, the Enclave-backed cache (owned by the auth broker), the
// sync engine, the presence probes, and the ssh runner.
type Daemon struct {
	broker   *auth.Broker
	engine   *engine.Engine
	probe    Probe
	runner   engine.SSHRunner
	state    StateLoader
	registry RegistryLoader
}

// Build wires the production daemon: Touch ID consent, the per-boot
// Enclave-backed key cache (opened here, owned by the broker), the sync engine,
// the presence probes, and the ssh runner. The returned closer is the cache's
// Close — it evicts every entry and drops the Enclave key; Serve calls it, but
// a caller that builds without serving must too.
func Build(ctx context.Context) (*Daemon, func(context.Context) error, error) {
	d, keyCache, err := build(ctx)
	if err != nil {
		return nil, nil, err
	}
	return d, keyCache.Close, nil
}

// build is Build with the key cache exposed, so lifecycle tests drive the real
// cache the daemon was wired over.
func build(ctx context.Context) (*Daemon, *cache.KeyCache, error) {
	store := state.New(paths.Config)
	// Load once here to fail fast on a malformed state file; handlers re-read it live.
	if _, err := store.Load(ctx); err != nil {
		return nil, nil, err
	}

	keyCache, err := cache.Open(ctx, helper.Bridge{})
	if err != nil {
		return nil, nil, err
	}
	runner := engine.NewExecSSHRunner()

	// synckitd owns the watch loop and reconcile tick; the engine records
	// applied digests through a standalone recorder.
	eng := engine.New(store, keyCache, runner, engine.NewDigestRecorder())

	d := New(cookie.TouchIDConsent{}, keyCache, eng, presence.Session, runner, store, store)
	// keybag_locked derives from the console session alone: the ioreg-only
	// probe keeps netstat off the doctor hot path.
	d.broker.KeybagProbe = presence.Console

	return d, keyCache, nil
}

// New builds a daemon over injected collaborators, for tests and for Build. The
// auth broker is constructed here over the same seams; Build pins its
// KeybagProbe to the ioreg-only read, and tests pin the broker's exported
// fields directly.
func New(consent cookie.Consent, c Cache, eng *engine.Engine, probe Probe, runner engine.SSHRunner, st StateLoader, reg RegistryLoader) *Daemon {
	return &Daemon{
		broker:   auth.NewBroker(consent, c, probe, runner, st),
		engine:   eng,
		probe:    probe,
		runner:   runner,
		state:    st,
		registry: reg,
	}
}

// Dispatcher builds the synckit Dispatcher with every peer and local method
// bound. The transport dispatches handlers concurrently, so a host mid-pass
// keeps answering its peers. Only sync and reconcile are registered exclusive:
// they run the flock-wrapped converge pass, queueing behind the same
// per-dispatcher mutex as svc.sync and svc.reconcile instead of contending on
// the non-reentrant flock. Everything else stays concurrent — request_consent
// above all, since a routed consent must be answerable while this host is
// itself mid-prime (the same-host routed-consent cycle). The shared in-process
// state behind the concurrent handlers locks internally; handleApply serializes
// per endpoint via the engine's apply lock, and the auth broker single-flights
// releases and serializes the Touch ID sheet.
func (d *Daemon) Dispatcher() *synckit.Dispatcher {
	dispatcher := synckit.NewDispatcher()
	// The typed sync contract synckitd drives over the resident socket, served
	// here so a cross-host svc.sync reuses the already-primed SE key.
	syncservice.RegisterConsumer(dispatcher, newSyncConsumer(d.engine, d.state, d.registry))
	// The bare fleet/local methods. sync and reconcile take the state flock,
	// so they are exclusive.
	dispatcher.RegisterExclusive("sync", d.handleSync)
	dispatcher.RegisterExclusive("reconcile", d.handleReconcile)
	dispatcher.Register("extract", d.handleExtract)
	dispatcher.Register("apply", d.handleApply)
	dispatcher.Register("whoami", d.handleWhoami)
	dispatcher.Register("prime_auth", d.handlePrimeAuth)
	dispatcher.Register("get_cookies", d.handleGetCookies)
	dispatcher.Register("get_web_storage", d.handleGetWebStorage)
	dispatcher.Register("auth_status", d.handleAuthStatus)
	dispatcher.Register("request_consent", d.handleRequestConsent)
	return dispatcher
}

// Serve runs the resident helper until ctx is canceled: it opens the resident
// collaborators (the SE wrapper among them), binds the RPC socket, arms the
// SIGUSR1 goroutine-dump listener, and answers the method set. On shutdown it
// drops the per-boot Enclave key and evicts the cache, so a leaked wrapped blob
// is unrecoverable off-box.
func Serve(ctx context.Context) error {
	d, closer, err := Build(ctx)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := closer(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "cookiesync: drop Enclave key on shutdown: %v\n", err)
		}
	}()

	dir, err := paths.Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir %s: %w", dir, err)
	}
	// SIGUSR1 → goroutine dump, so the next wedge is inspectable without a
	// restart; registers only SIGUSR1, leaving TERM/INT handling untouched.
	if err := debug.DumpOnSIGUSR1(ctx, filepath.Join(dir, "debug")); err != nil {
		return err
	}
	sock, err := paths.SockPath()
	if err != nil {
		return err
	}
	ln, err := synckit.Listen(sock)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	return synckit.Serve(ctx, ln, d.Dispatcher())
}

// endpointID is an endpoint's stable identity, host:browser:profile — the cache
// key and the routed-consent endpoint id.
func endpointID(host, browser, profile string) string {
	return string(state.Endpoint{Host: host, Browser: browser, Profile: profile}.ID())
}

// meshSelf resolves this host's ssh target from the shared synckit mesh. Every
// cache key and consent-endpoint binding keys on it, never on this host's
// written-through self_target mirror, so self is consistent on a freshly-joined
// host whose state has not yet been stamped.
func meshSelf(ctx context.Context) (string, error) {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return "", err
	}
	return self, nil
}

// stringParam reads a required string param, erroring when absent or the wrong
// type so a malformed request fails loudly rather than defaulting silently.
func stringParam(params map[string]any, key string) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing required param %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("param %q is %T, want string", key, v)
	}
	return s, nil
}

// optionalString reads a string param, returning fallback when absent, null, or
// empty — matching the Python params.get(key, default).
func optionalString(params map[string]any, key, fallback string) string {
	if v, ok := params[key].(string); ok && v != "" {
		return v
	}
	return fallback
}
