package cli

import "testing"

// TestResolveRequestor proves the stable-requestor derivation. Every case sets both
// resolver-read env vars so the ambient CLAUDE_CODE_SESSION_ID never leaks in.
func TestResolveRequestor(t *testing.T) {
	tests := []struct {
		name      string
		requestor string
		claudeSID string
		wantRef   string
		wantOK    bool
	}{
		{
			name:      "explicit requestor wins over an agent session",
			requestor: "my-own-token",
			claudeSID: "a3283ae1-b524-48c3-ab30-42eb6e1ab6e6",
			wantRef:   "my-own-token",
			wantOK:    true,
		},
		{
			name:      "claude code session derives a short reference",
			requestor: "",
			claudeSID: "a3283ae1-b524-48c3-ab30-42eb6e1ab6e6",
			wantRef:   "Claude Code · a3283ae1",
			wantOK:    true,
		},
		{
			name:      "neither set defers to the daemon",
			requestor: "",
			claudeSID: "",
			wantRef:   "",
			wantOK:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(requestorEnv, tc.requestor)
			t.Setenv("CLAUDE_CODE_SESSION_ID", tc.claudeSID)
			ref, ok := resolveRequestor()
			if ref != tc.wantRef || ok != tc.wantOK {
				t.Fatalf("resolveRequestor() = %q, %v, want %q, %v", ref, ok, tc.wantRef, tc.wantOK)
			}
		})
	}
}

// TestResolveRequestorPrefersNameEnv exercises the nameEnv branch: a set session-name
// env wins over the raw id's short reference. It swaps agentSessions for the duration
// rather than adding a production entry with a name env that does not exist.
func TestResolveRequestorPrefersNameEnv(t *testing.T) {
	const idEnv, nameEnv = "COOKIESYNC_TEST_AGENT_ID", "COOKIESYNC_TEST_AGENT_NAME"
	saved := agentSessions
	agentSessions = []struct{ label, idEnv, nameEnv string }{
		{"Test Agent", idEnv, nameEnv},
	}
	t.Cleanup(func() { agentSessions = saved })

	t.Setenv(requestorEnv, "")
	t.Setenv(idEnv, "raw-9f8e-id")
	t.Setenv(nameEnv, "friendly")

	ref, ok := resolveRequestor()
	if ref != "Test Agent · friendly" || !ok {
		t.Fatalf("resolveRequestor() = %q, %v, want %q, true", ref, ok, "Test Agent · friendly")
	}
}

// TestShortRef proves the id-to-reference reduction over UUID, sub-eight, and
// hyphenless ids — none panic.
func TestShortRef(t *testing.T) {
	tests := []struct {
		name, id, want string
	}{
		{"uuid caps to first segment eight", "a3283ae1-b524-48c3-ab30-42eb6e1ab6e6", "a3283ae1"},
		{"short id untouched", "ab", "ab"},
		{"hyphenless caps to eight", "0123456789abcdef", "01234567"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shortRef(tc.id); got != tc.want {
				t.Fatalf("shortRef(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}
