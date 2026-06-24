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
// origin — what the CLI on this box invokes: prime_auth obtains the Safe Storage key
// (behind one Touch ID tap when a session is live, else by routing the user-presence
// gate to the active peer and then releasing this host's own key non-interactively)
// and caches it; get_cookies renders one or more urls' cookies from the cached key,
// merged into one set; auth_status reports cache warmth; request_consent shows the
// Touch ID prompt for the named browser to the person at this machine and echoes the
// requester's nonce + endpoint to bind the approval — the key never crosses hosts.
//
// Every collaborator (consent gate, key cache, sync engine, session probe, ssh
// runner, state store, and the clock) is injected behind a seam, so the whole
// dispatcher runs in unit tests against fakes without a real macOS API, ssh, or
// cookie store. The watch loop that drives the engine on local store changes is the
// next cycle; Serve leaves a clean seam to add it alongside the RPC server.
package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	synckit "github.com/yasyf/synckit/rpc"
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
// shares plus the put prime_auth seeds. Defined here, where it is consumed.
type Cache interface {
	engine.KeyCache
	// Put wraps key and records it under endpointID with the given TTL.
	Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) error
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
	consent cookie.Consent
	cache   Cache
	engine  *engine.Engine
	probe   Probe
	runner  engine.SSHRunner
	state   StateLoader

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
	if err != nil {
		return nil, nil, err
	}
	keyCache := cache.NewKeyCache(wrapper)
	runner := engine.NewExecSSHRunner()
	eng := engine.New(store, keyCache, runner, engine.NewDigestRecorder())

	d := New(cookie.TouchIDConsent{}, keyCache, eng, ProbeSession, runner, store)

	closer := func(ctx context.Context) error {
		keyCache.EvictAll()
		return wrapper.Close(ctx)
	}
	return d, closer, nil
}

// New builds a daemon over injected collaborators, for tests and for Build. The nonce
// source defaults to crypto/rand; override the field after construction to pin it.
func New(consent cookie.Consent, c Cache, eng *engine.Engine, probe Probe, runner engine.SSHRunner, st StateLoader) *Daemon {
	return &Daemon{
		consent:  consent,
		cache:    c,
		engine:   eng,
		probe:    probe,
		runner:   runner,
		state:    st,
		newNonce: newNonce,
	}
}

// Dispatcher builds the synckit Dispatcher with every peer and local method bound. The
// transport serializes handlers behind one mutex, so two requests never race the
// shared cache or the cross-process state flock.
func (d *Daemon) Dispatcher() *synckit.Dispatcher {
	dispatcher := synckit.NewDispatcher()
	dispatcher.Register("sync", d.handleSync)
	dispatcher.Register("reconcile", d.handleReconcile)
	dispatcher.Register("extract", d.handleExtract)
	dispatcher.Register("apply", d.handleApply)
	dispatcher.Register("whoami", d.handleWhoami)
	dispatcher.Register("prime_auth", d.handlePrimeAuth)
	dispatcher.Register("get_cookies", d.handleGetCookies)
	dispatcher.Register("auth_status", d.handleAuthStatus)
	dispatcher.Register("request_consent", d.handleRequestConsent)
	return dispatcher
}

// Serve runs the daemon until ctx is canceled: it opens the resident collaborators
// (the SE wrapper among them), binds the RPC socket, and answers the method set. On
// shutdown it drops the per-boot Enclave key and evicts the cache, so a leaked wrapped
// blob is unrecoverable off-box. The watch loop that converges on local store changes
// is the next cycle and joins here alongside the RPC server.
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
