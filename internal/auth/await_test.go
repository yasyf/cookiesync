package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasyf/synckit/presence"
)

func awaitBroker(probe Probe, runner SSHRunner) *Broker {
	b := newTestBroker(&fakeConsent{}, newFakeCache(), probe, runner, stateWith("me@laptop", ""))
	b.LocalAwaitInterval = time.Millisecond
	b.PeerAwaitInterval = time.Millisecond
	return b
}

func TestAwaitApproverReturnsAtOnceForAnAttendedSession(t *testing.T) {
	fakeMesh(t, "me@laptop", "you@desktop")
	runner := &approverMesh{}
	b := awaitBroker(staticProbe(liveSession(currentUser(t))), runner)

	if err := b.AwaitApprover(context.Background()); err != nil {
		t.Fatalf("AwaitApprover: %v", err)
	}
	if probed := runner.probedTargets(); len(probed) != 0 {
		t.Fatalf("whoami probes = %v, want none for an attended local session", probed)
	}
}

func TestAwaitApproverParksUntilTheLocalSessionUnlocks(t *testing.T) {
	fakeMesh(t, "me@laptop")
	var reads atomic.Int32
	probe := func(context.Context) (presence.SessionSnapshot, error) {
		if reads.Add(1) < 3 {
			return presence.SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: currentUser(t)}, nil
		}
		return liveSession(currentUser(t)), nil
	}
	b := awaitBroker(probe, &approverMesh{})

	if err := b.AwaitApprover(context.Background()); err != nil {
		t.Fatalf("AwaitApprover: %v", err)
	}
	if got := reads.Load(); got != 3 {
		t.Fatalf("local session reads = %d, want 3", got)
	}
}

func TestAwaitApproverParksUntilAPeerGoesLive(t *testing.T) {
	fakeMesh(t, "me@laptop", "you@desktop")
	runner := &flippingWhoami{after: 3}
	b := awaitBroker(staticProbe(presence.SessionSnapshot{}), runner)

	if err := b.AwaitApprover(context.Background()); err != nil {
		t.Fatalf("AwaitApprover: %v", err)
	}
	if got := runner.calls.Load(); got != 3 {
		t.Fatalf("whoami probes = %d, want 3", got)
	}
}

func TestAwaitApproverTimesOutWhenNothingGoesLive(t *testing.T) {
	fakeMesh(t, "me@laptop", "you@desktop")
	b := awaitBroker(staticProbe(presence.SessionSnapshot{}), &approverMesh{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := b.AwaitApprover(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AwaitApprover = %v, want context.DeadlineExceeded", err)
	}
}

func TestAwaitApproverFailsOnAMalformedWhoami(t *testing.T) {
	fakeMesh(t, "me@laptop", "you@desktop")
	runner := &approverMesh{whoami: map[string]string{"you@desktop": "not json"}}
	b := awaitBroker(staticProbe(presence.SessionSnapshot{}), runner)

	if err := b.AwaitApprover(context.Background()); err == nil {
		t.Fatalf("AwaitApprover = nil, want the whoami parse failure")
	}
}

type flippingWhoami struct {
	after int32
	calls atomic.Int32
}

func (r *flippingWhoami) Run(context.Context, string, string, []byte) (string, error) {
	if r.calls.Add(1) < r.after {
		return deadWhoami, nil
	}
	return liveWhoami, nil
}
