//go:build linux

package auth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commLimit = 15

func ownComm(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	name := filepath.Base(exe)
	if len(name) > commLimit {
		name = name[:commLimit]
	}
	return name
}

func TestProcessNameReadsProcComm(t *testing.T) {
	got, err := processName(context.Background(), os.Getpid())
	if err != nil {
		t.Fatalf("processName: %v", err)
	}
	if want := ownComm(t); strings.TrimSpace(got) != want {
		t.Fatalf("processName = %q, want %q", strings.TrimSpace(got), want)
	}
}

func TestRequestorReasonOnLinux(t *testing.T) {
	const reason = "sync them across your machines"
	tests := []struct {
		name      string
		requestor string
		pid       int
		hasPID    bool
		want      string
	}{
		{"token requestor names itself without a process read", "req:agent-1", 0, false, reason + " for agent-1"},
		{"peer pid resolves the calling process name", "sid:7", os.Getpid(), true, reason + " for " + ownComm(t)},
		{"no peer pid leaves the reason unchanged", "local", 0, false, reason},
		{"a pid with no process leaves the reason unchanged", "sid:7", 0, true, reason},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestorReason(context.Background(), tc.requestor, reason, tc.pid, tc.hasPID); got != tc.want {
				t.Fatalf("requestorReason = %q, want %q", got, tc.want)
			}
		})
	}
}
