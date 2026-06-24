package daemon

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
)

// ioregArgv reads the Root node's IOConsoleUsers/IOConsoleLocked as an XML plist on
// stdout. It answers from any audit session — including a launchd daemon in a
// different session — so it stays correct on a headless box.
var ioregArgv = []string{"ioreg", "-n", "Root", "-d1", "-a"}

// Console-session plist keys, matching the macOS CoreGraphics session dictionary.
const (
	onConsoleKey    = "kCGSSessionOnConsoleKey"
	userNameKey     = "kCGSSessionUserNameKey"
	screenLockedKey = "CGSSessionScreenIsLocked"
)

// SessionSnapshot is a point-in-time read of this host's console GUI session: whether
// a GUI session owns the physical console, whether its screen is locked, and the
// console user's short name (empty when no GUI session is attached). It mirrors the
// Python SessionSnapshot.
type SessionSnapshot struct {
	OnConsole   bool
	Locked      bool
	ConsoleUser string
}

// Probe reads this host's console GUI session. It is injected so the session logic
// runs in tests against synthetic snapshots without touching macOS.
type Probe func(ctx context.Context) (SessionSnapshot, error)

// parseSession decodes an ioreg XML plist into a snapshot, matching the Python
// parse_session: the first on-console session decides; locked is the root flag OR
// that session's own screen-locked flag; an absent on-console session is headless.
func parseSession(payload []byte) (SessionSnapshot, error) {
	root, err := decodePlist(payload)
	if err != nil {
		return SessionSnapshot{}, err
	}
	dict, ok := root.(map[string]any)
	if !ok {
		return SessionSnapshot{}, fmt.Errorf("ioreg plist root is %T, want a dict", root)
	}
	users, _ := dict["IOConsoleUsers"].([]any)
	for _, raw := range users {
		sess, ok := raw.(map[string]any)
		if !ok || !asBool(sess[onConsoleKey]) {
			continue
		}
		return SessionSnapshot{
			OnConsole:   true,
			Locked:      asBool(dict["IOConsoleLocked"]) || asBool(sess[screenLockedKey]),
			ConsoleUser: asString(sess[userNameKey]),
		}, nil
	}
	return SessionSnapshot{}, nil
}

// ProbeSession is the production Probe: it shells ioreg and parses the plist.
func ProbeSession(ctx context.Context) (SessionSnapshot, error) {
	cmd := exec.CommandContext(ctx, ioregArgv[0], ioregArgv[1:]...) //nolint:gosec // G204: ioregArgv is a fixed argv, not user-supplied.
	out, err := cmd.Output()
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("run ioreg: %w", err)
	}
	return parseSession(out)
}

// HasActiveSession reports whether a real person is at this host's keyboard right now:
// a GUI session holds the console, its screen is unlocked, and the console user is the
// user this process runs as. A locked screen, a headless box, or another user holding
// the console via fast user switching all return false. It mirrors the Python
// has_active_session.
func HasActiveSession(ctx context.Context, probe Probe) (bool, error) {
	snapshot, err := probe(ctx)
	if err != nil {
		return false, err
	}
	me, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("resolve current user: %w", err)
	}
	return snapshot.OnConsole && !snapshot.Locked && snapshot.ConsoleUser == me.Username, nil
}

// sessionSummary is this host's console session state shaped for the whoami RPC,
// byte-for-byte the Python session_summary: {"on_console", "locked", "console_user"}.
// console_user is null (a nil any) when no GUI session is attached.
func sessionSummary(ctx context.Context, probe Probe) (map[string]any, error) {
	snapshot, err := probe(ctx)
	if err != nil {
		return nil, err
	}
	var consoleUser any
	if snapshot.ConsoleUser != "" {
		consoleUser = snapshot.ConsoleUser
	}
	return map[string]any{
		"on_console":   snapshot.OnConsole,
		"locked":       snapshot.Locked,
		"console_user": consoleUser,
	}, nil
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
