//go:build linux

package daemon

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"
	"github.com/yasyf/synckit/presence"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	consentkit "github.com/yasyf/synckit/consent"
)

func approvingConsent() *fakeConsent {
	return &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
}

func TestLinuxPlatformWiresTheLinuxProviders(t *testing.T) {
	host := hostPlatform()
	if _, ok := host.consent.(cookie.LinuxConsent); !ok {
		t.Fatalf("consent provider = %T, want cookie.LinuxConsent", host.consent)
	}
	if _, ok := host.sealer.(cache.NoEnclave); !ok {
		t.Fatalf("cache sealer = %T, want cache.NoEnclave", host.sealer)
	}
}

func TestLinuxProbesReportUnattendedWithoutError(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	host := hostPlatform()
	probes := []struct {
		name  string
		probe Probe
	}{
		{"routing probe", host.session},
		{"keybag probe", host.keybag},
	}
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{"live context", context.Background()},
		{"cancelled context", cancelled},
	}
	for _, p := range probes {
		for _, c := range contexts {
			t.Run(p.name+" under a "+c.name, func(t *testing.T) {
				snap, err := p.probe(c.ctx)
				if err != nil {
					t.Fatalf("probe error = %v, want nil: an erroring probe takes the local-prompt branch", err)
				}
				if snap != (SessionSnapshot{}) {
					t.Fatalf("snapshot = %+v, want the zero unattended snapshot", snap)
				}
				attended, err := presence.Attended(snap)
				if err != nil {
					t.Fatalf("Attended: %v", err)
				}
				if attended {
					t.Fatal("a linux host must never read as attended")
				}
			})
		}
	}
}

func TestLinuxWhoamiNeverReportsALiveConsole(t *testing.T) {
	d := New(approvingConsent(), newFakeCache(), nil, hostPlatform().session, &recordingRunner{}, fixedState{}, fixedState{})
	got, err := d.handleWhoami(context.Background(), nil)
	if err != nil {
		t.Fatalf("handleWhoami: %v", err)
	}
	const want = `{"console_user":null,"locked":false,"on_console":false,"screen_shared":false}`
	if marshalResult(t, got) != want {
		t.Fatalf("whoami = %s, want %s", marshalResult(t, got), want)
	}
}

func TestLinuxHostNeverApprovesConsent(t *testing.T) {
	fakeMesh(t, "me@vm")
	params := map[string]any{"browser": "chrome", "nonce": "n", "endpoint": "them@mac:chrome:Default"}
	tests := []struct {
		name   string
		handle func(*Daemon) (any, error)
	}{
		{"request_consent", func(d *Daemon) (any, error) { return d.handleRequestConsent(context.Background(), params) }},
		{"request_bridge_consent", func(d *Daemon) (any, error) {
			return d.handleRequestBridgeConsent(context.Background(), params)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name+" over a consent that would approve", func(t *testing.T) {
			consent := approvingConsent()
			d := New(consent, newFakeCache(), nil, hostPlatform().session, &recordingRunner{}, fixedState{}, fixedState{})
			got, err := tc.handle(d)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if marshalResult(t, got) != `{"status":"unavailable"}` {
				t.Fatalf("%s = %s, want unavailable", tc.name, marshalResult(t, got))
			}
			if len(consent.promptedReasons) != 0 || consent.biometricCalls.Load() != 0 || consent.unpromptedCalled != 0 {
				t.Fatalf("%s reached the consent gate: prompts %v, biometric %d, unprompted %d",
					tc.name, consent.promptedReasons, consent.biometricCalls.Load(), consent.unpromptedCalled)
			}
		})
		t.Run(tc.name+" over the linux consent", func(t *testing.T) {
			host := hostPlatform()
			d := New(host.consent, newFakeCache(), nil, host.session, &recordingRunner{}, fixedState{}, fixedState{})
			got, err := tc.handle(d)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if marshalResult(t, got) != `{"status":"unavailable"}` {
				t.Fatalf("%s = %s, want unavailable", tc.name, marshalResult(t, got))
			}
		})
	}
}

func TestLinuxLocalReleaseNeverPromptsLocally(t *testing.T) {
	self := "me@vm"
	fakeMesh(t, self)
	st := stateWith(self, "", state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"})
	consent := approvingConsent()
	keys := newFakeCache()
	runner := &recordingRunner{}
	d := New(consent, keys, nil, hostPlatform().session, runner, fixedState{st: st}, fixedState{st: st})

	_, _, err := d.primeAuth(context.Background(), "req:agent-1", "chrome", "Default", consentReason, releaseLocal)
	var authRequired *AuthRequired
	if !errors.As(err, &authRequired) {
		t.Fatalf("primeAuth with no approver = %v, want AuthRequired", err)
	}
	if verdict := auth.Classify(err); verdict != consentkit.VerdictUnavailable {
		t.Fatalf("verdict = %v, want unavailable", verdict)
	}
	if len(consent.promptedReasons) != 0 || consent.biometricCalls.Load() != 0 || consent.unpromptedCalled != 0 {
		t.Fatalf("a cold linux host must not reach its own gate or key: prompts %v, biometric %d, unprompted %d",
			consent.promptedReasons, consent.biometricCalls.Load(), consent.unpromptedCalled)
	}
	if d.granted("req:agent-1", "chrome") {
		t.Fatal("a failed release must not grant")
	}
	if keys.putCalls() != 0 {
		t.Fatalf("a failed release cached %d keys", keys.putCalls())
	}
}

func TestLinuxCacheOpensInTheMemoryTier(t *testing.T) {
	ctx := context.Background()
	keyCache, err := cache.Open(ctx, hostPlatform().sealer)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	if !keyCache.Degraded() {
		t.Fatal("the linux key cache must open degraded")
	}
	degraded, err := keyCache.Put(ctx, "me@vm:chrome:Default", []byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !degraded || !keyCache.Degraded() {
		t.Fatalf("Put published degraded=%v, cache degraded=%v; the linux cache must never leave the memory tier", degraded, keyCache.Degraded())
	}
	if err := keyCache.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestHelperSpecRunsHelperServeUnderTheClientLabel(t *testing.T) {
	spec, err := HelperSpec()
	if err != nil {
		t.Fatalf("HelperSpec: %v", err)
	}
	client, err := helperruntime.Spec(paths.ToolName, daemonkit.Program{}, 0)
	if err != nil {
		t.Fatalf("client spec: %v", err)
	}
	if spec.Label != client.Label {
		t.Fatalf("label = %q, want the label clients open, %q", spec.Label, client.Label)
	}
	if !slices.Equal(spec.Args, []string{"helper-serve"}) {
		t.Fatalf("args = %v, want [helper-serve]", spec.Args)
	}
	if spec.Program == (daemonkit.Program{}) {
		t.Fatal("the supervised spec must carry the stable program")
	}
	if spec.Restart != daemonkit.RestartAlways {
		t.Fatalf("restart = %v, want RestartAlways", spec.Restart)
	}
}
