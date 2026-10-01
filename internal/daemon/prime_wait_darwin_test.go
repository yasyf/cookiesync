package daemon

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func waitingDaemon(t *testing.T, consent *fakeConsent, probe Probe) *Daemon {
	t.Helper()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	d := New(consent, newFakeCache(), nil, probe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.broker.LocalAwaitInterval = time.Millisecond
	d.broker.PeerAwaitInterval = time.Millisecond
	return d
}

func TestPrimeAuthWaitOutcomes(t *testing.T) {
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	live := staticProbe(liveSession(currentUser(t)))
	tests := []struct {
		name    string
		consent *fakeConsent
		probe   Probe
		want    map[string]any
		prompts int
	}{
		{
			name:    "approved",
			consent: &fakeConsent{key: key},
			probe:   live,
			want:    map[string]any{"status": "approved", "primed": true, "endpoint": endpointID("me@laptop", "chrome", "Default")},
			prompts: 1,
		},
		{
			name:    "denied",
			consent: &fakeConsent{obtainErr: &cookie.ConsentError{Msg: "user canceled"}},
			probe:   live,
			want:    map[string]any{"status": "denied", "reason": "user canceled"},
			prompts: 1,
		},
		{
			name:    "no approver came live",
			consent: &fakeConsent{key: key},
			probe:   staticProbe(SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: currentUser(t)}),
			want:    map[string]any{"status": "waiting"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := waitingDaemon(t, tt.consent, tt.probe)

			got, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome", "wait": 0.05})
			if err != nil {
				t.Fatalf("handlePrimeAuth: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("reply = %v, want %v", got, tt.want)
			}
			if prompts := len(tt.consent.promptedReasons); prompts != tt.prompts {
				t.Fatalf("prompts = %d, want %d", prompts, tt.prompts)
			}
		})
	}
}

func TestPrimeAuthWaitRejectsANonNumericWait(t *testing.T) {
	d := waitingDaemon(t, &fakeConsent{}, staticProbe(liveSession(currentUser(t))))

	if _, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome", "wait": "10m"}); err == nil {
		t.Fatalf("handlePrimeAuth with wait \"10m\" = nil error, want a type refusal")
	}
}
