// Package daemon is the resident cookiesync daemon: the unix-socket RPC server, the
// method handlers, and the routed-consent gate. It listens on paths.SockPath via the
// shared synckit/rpc transport (the frozen {method, params} -> {ok, result, error}
// wire) and dispatches the bimodal method set.
//
// The method set splits in two. Peer methods carry an origin and are how peers drive
// this host over ssh: sync converges the local union (suppressing the origin),
// reconcile runs a full pass, extract returns this host's decrypted cookies as wire
// records (priming auth if the key is cold), apply ingests a merged wire set, and
// whoami reports this host's console session. Local methods are terminal and carry no
// origin — what the CLI on this box invokes: prime_auth obtains the Safe Storage keys
// (behind one Touch ID evaluation covering every tracked local browser when a session
// is live, else by routing the user-presence gate to the active peer and then
// releasing this host's own key non-interactively) and caches them; get_cookies
// renders one or more urls' cookies, merged into one set, behind the same gate.
// Authorization is per requesting principal, not global cache warmth: a warm key is
// served silently only while the requestor holds a live consent grant for the
// browser, and a release grants its requestor every browser it covered;
// auth_status reports cache warmth and Secure-Enclave degradation; request_consent
// shows the Touch ID prompt for the named browser to the person at this machine,
// warms this host's own cache off the same tap, and echoes the requester's nonce +
// endpoint to bind the approval — the key never crosses hosts.
//
// Every collaborator (consent gate, key cache, sync engine, session probe, ssh
// runner, state store, and the clock) is injected behind a seam, so the whole
// dispatcher runs in unit tests against fakes without a real macOS API, ssh, or
// cookie store. The watch loop, reconcile tick, and host mesh now live in synckitd,
// which shells `cookiesync sync|reconcile`; those CLIs dial this resident helper
// over the RPC socket (see Serve), keeping the SE key cache and Touch ID consent
// gate — the two things a fresh subprocess cannot hold — resident.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	synckit "github.com/yasyf/synckit/rpc"
	"github.com/yasyf/synckit/syncservice"
	"golang.org/x/sync/singleflight"
)

// consentReason is the default Touch ID prompt reason for a prime_auth with no
// caller-supplied reason — the frozen wording the Python daemon uses.
const consentReason = "sync them across your Macs"

// defaultProfile is the profile a method assumes when the request omits one, matching
// the Python DEFAULT_PROFILE.
const defaultProfile = "Default"

// AuthRequired reports that the local key cache is cold and no live session — local or
// routed — could release the key. It is the error the consent path fails closed with,
// and a routed approval that fails to bind (a nonce or endpoint mismatch) raises it
// too: an unbound approval is a security failure, never a retry. The caller branches
// on it via errors.As.
type AuthRequired struct {
	Msg string
}

func (e *AuthRequired) Error() string { return e.Msg }

// Cache is the slice of the key cache the daemon drives: the warmth read the engine
// shares, the put prime_auth seeds, and the degradation state auth_status surfaces.
// Defined here, where it is consumed.
type Cache interface {
	engine.KeyCache
	// Put wraps key and records it under endpointID with the given TTL.
	Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) error
	// Degraded reports whether cached keys are identity-wrapped in process memory
	// because the Secure Enclave refused its per-boot key at open; a later Put heals it.
	Degraded() bool
}

// StateLoader loads the cookiesync state. It is the read seam the handlers resolve the
// self target, settings, and peer mesh through; injected so handlers run against a
// fixture state.
type StateLoader interface {
	Load(ctx context.Context) (*state.State, error)
}

// Daemon holds every collaborator behind an injected seam so the dispatcher runs in
// unit tests against fakes. In production it is built by Build with the real consent
// gate, the Enclave-backed cache, the sync engine, the ioreg session probe, and the
// ssh runner.
type Daemon struct {
	consent  cookie.Consent
	cache    Cache
	engine   *engine.Engine
	probe    Probe
	runner   engine.SSHRunner
	state    StateLoader
	registry RegistryLoader

	// batchFlight collapses concurrent primeAuth calls into one flight per release
	// mode and requestor, so a burst of cold primes from one principal — same
	// endpoint or distinct — costs one consent evaluation covering every tracked
	// local browser, while distinct principals each face their own tap. The mode
	// key keeps an approver's release (an inbound request_consent) off the local
	// flight, so an inbound approval never parks behind this host's own outbound
	// routed prime (the same-host routed-consent cycle).
	batchFlight singleflight.Group

	// grants authorizes requestors per browser: requestor + ":" + browser name →
	// expiry. A release grants the flight's requestor every browser it covered; a
	// warm cached key is served silently only inside a live grant — cache warmth
	// alone never authorizes a new principal. Guarded by grantMu, pruned on read.
	grantMu sync.Mutex
	grants  map[string]time.Time

	// promptGate serializes the interactive Touch ID sheets across flights — a
	// local prime and an inbound approval never stack two consent sheets. It is
	// held only around the consent.ObtainKeys call inside releaseAllLocal, never
	// across routedRelease or any outbound ssh, so the same-host routed-consent
	// cycle cannot deadlock on it.
	promptGate sync.Mutex

	// newNonce mints a fresh routed-consent nonce. It is a field so a test can pin
	// the nonce and assert the echo binding; production uses the crypto/rand source.
	newNonce func() (string, error)
}

// Build wires the production daemon: Touch ID consent, the per-boot Enclave-backed
// cache (its wrapper opened here and dropped by Serve on shutdown), the sync engine,
// the ioreg session probe, and the ssh runner. The returned closer drops the Enclave
// key; Serve calls it, but a caller that builds without serving must call it too.
func Build(ctx context.Context) (*Daemon, func(context.Context) error, error) {
	store := state.New(paths.Config)
	// Load once here to fail fast on a malformed state file; handlers re-read it live.
	if _, err := store.Load(ctx); err != nil {
		return nil, nil, err
	}

	wrapper, err := cache.OpenWrapper(ctx, helper.Bridge{})
	switch {
	case errors.Is(err, cache.ErrSEPresenceUnavailable):
		slog.WarnContext(ctx, "Secure Enclave presence unavailable — screen-shared/locked; using in-memory key cache this session", "err", err)
	case err != nil:
		return nil, nil, err
	}
	keyCache := cache.NewKeyCache(wrapper)
	runner := engine.NewExecSSHRunner()

	// synckitd owns the watch loop and reconcile tick now, so this helper runs no
	// local watch engine to echo to: the engine records applied digests through a
	// standalone recorder. The fingerprint that dedups a converge's own write is
	// re-derived by `cookiesync list --json`, which synckitd shells.
	eng := engine.New(store, keyCache, runner, engine.NewDigestRecorder())

	d := New(cookie.TouchIDConsent{}, keyCache, eng, ProbeSession, runner, store, store)

	closer := func(ctx context.Context) error {
		keyCache.EvictAll()
		return wrapper.Close(ctx)
	}
	return d, closer, nil
}

// New builds a daemon over injected collaborators, for tests and for Build. The nonce
// source defaults to crypto/rand; override the field after construction to pin it.
func New(consent cookie.Consent, c Cache, eng *engine.Engine, probe Probe, runner engine.SSHRunner, st StateLoader, reg RegistryLoader) *Daemon {
	return &Daemon{
		consent:  consent,
		cache:    c,
		engine:   eng,
		probe:    probe,
		runner:   runner,
		state:    st,
		registry: reg,
		grants:   map[string]time.Time{},
		newNonce: newNonce,
	}
}

// Dispatcher builds the synckit Dispatcher with every peer and local method bound.
// The transport dispatches handlers concurrently, so a host mid-pass keeps answering
// its peers. Only sync and reconcile are registered exclusive: they run the
// flock-wrapped converge pass, queueing behind the same per-dispatcher mutex as
// svc.sync and svc.reconcile instead of contending on the non-reentrant flock.
// Everything else stays concurrent — request_consent above all, since a routed
// consent must be answerable while this host is itself mid-prime (the same-host
// routed-consent cycle). The shared in-process state behind the concurrent handlers
// (key cache, digest recorder) locks internally; handleApply serializes per endpoint
// via the engine's apply lock — shared with a converge pass's local writes — primeAuth
// single-flights per release mode and requestor via batchFlight, and the interactive
// Touch ID sheet serializes across flights behind promptGate.
func (d *Daemon) Dispatcher() *synckit.Dispatcher {
	dispatcher := synckit.NewDispatcher()
	// The typed sync contract synckitd drives: svc.capabilities/list/reconcile/sync/
	// get_state, served IN this warm-key resident helper so a cross-host svc.sync reuses
	// the already-primed Secure-Enclave key rather than re-priming in a fresh subprocess.
	syncservice.RegisterConsumer(dispatcher, newSyncConsumer(d.engine, d.state, d.registry))
	// The bare fleet/local methods: extract/apply (the cookie value-union pull/push the
	// peer SSHBackend drives), whoami, prime_auth, get_cookies, auth_status,
	// request_consent. sync and reconcile stay too — the `cookiesync rpc sync|reconcile`
	// fleet CLI still reaches them — and take the state flock, so they are exclusive.
	dispatcher.RegisterExclusive("sync", d.handleSync)
	dispatcher.RegisterExclusive("reconcile", d.handleReconcile)
	dispatcher.Register("extract", d.handleExtract)
	dispatcher.Register("apply", d.handleApply)
	dispatcher.Register("whoami", d.handleWhoami)
	dispatcher.Register("prime_auth", d.handlePrimeAuth)
	dispatcher.Register("get_cookies", d.handleGetCookies)
	dispatcher.Register("auth_status", d.handleAuthStatus)
	dispatcher.Register("request_consent", d.handleRequestConsent)
	return dispatcher
}

// Serve runs the resident helper until ctx is canceled: it opens the resident
// collaborators (the SE wrapper among them), binds the RPC socket, and answers the
// method set. On shutdown it drops the per-boot Enclave key and evicts the cache, so a
// leaked wrapped blob is unrecoverable off-box. synckitd drives convergence by shelling
// the cookiesync CLI, which dials this socket — the helper itself runs no watch loop.
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

// endpointID is an endpoint's stable identity, host:browser:profile — the cache key
// and the routed-consent endpoint id. It is the state.Endpoint identity, kept as a
// free function so the handlers read uniformly.
func endpointID(host, browser, profile string) string {
	return string(state.Endpoint{Host: host, Browser: browser, Profile: profile}.ID())
}

// meshSelf resolves this host's ssh target from the shared synckit mesh. Every cache
// key and consent-endpoint binding keys on it, never on this host's written-through
// self_target mirror, so self is consistent on a freshly-joined host whose state has
// not yet been stamped. The peer fan-out is the same mesh, read in consent.go.
func meshSelf(ctx context.Context) (string, error) {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return "", err
	}
	return self, nil
}

// stringParam reads a required string param, erroring when absent or the wrong type so
// a malformed request fails loudly rather than defaulting silently.
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

// optionalString reads a string param, returning fallback when absent, null, or empty
// — matching the Python params.get(key, default) / `params.get(key) or default`.
func optionalString(params map[string]any, key, fallback string) string {
	if v, ok := params[key].(string); ok && v != "" {
		return v
	}
	return fallback
}
