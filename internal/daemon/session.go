package daemon

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
)

// ioregArgv reads the Root node's IOConsoleUsers/IOConsoleLocked as an XML plist on
// stdout. It answers from any audit session — including a launchd daemon in a
// different session — so it stays correct on a headless box.
var ioregArgv = []string{"ioreg", "-n", "Root", "-d1", "-a"}

var screenShareArgv = []string{"netstat", "-anv", "-p", "tcp"}

// Console-session plist keys, matching the macOS CoreGraphics session dictionary.
const (
	onConsoleKey    = "kCGSSessionOnConsoleKey"
	userNameKey     = "kCGSSessionUserNameKey"
	screenLockedKey = "CGSSessionScreenIsLocked"
)

// netstat -anv -p tcp columns and vocabulary. Screen Sharing (VNC) serves on TCP 5900:
// an inbound session shows this host's local address on that port in the ESTABLISHED
// state. netstat's tabular output puts the local address at field 3 and the connection
// state at field 5 (0-indexed) and prefaces its rows with a "Proto ..." header line.
const (
	screenSharePort  = ".5900"
	establishedState = "ESTABLISHED"
	netstatHeader    = "Proto"
	localAddrField   = 3
	stateField       = 5
)

// SessionSnapshot is a point-in-time read of this host's console GUI session: whether
// a GUI session owns the physical console, whether its screen is locked, the console
// user's short name (empty when no GUI session is attached), and whether an inbound
// screen share is mirroring the console. It extends the Python SessionSnapshot with the
// screen-share signal.
type SessionSnapshot struct {
	OnConsole    bool
	Locked       bool
	ConsoleUser  string
	ScreenShared bool
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

// parseScreenShare reports whether netstat shows an inbound Screen Sharing session into
// this host: some socket's local address is on the VNC port .5900 in the ESTABLISHED
// state. Both hosts LISTEN on *.5900 whenever Screen Sharing is enabled, so a LISTEN row
// is the idle listener rather than a live session — only ESTABLISHED counts, else every
// such host would look shared. A table with no matching row is legitimately not shared;
// a payload with no netstat header at all is malformed and errors, mirroring
// parseSession's fail-loud on a structurally invalid read.
func parseScreenShare(payload []byte) (bool, error) {
	sawHeader := false
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == netstatHeader {
			sawHeader = true
			continue
		}
		if len(fields) <= stateField {
			continue
		}
		if strings.HasSuffix(fields[localAddrField], screenSharePort) && fields[stateField] == establishedState {
			return true, nil
		}
	}
	if !sawHeader {
		return false, fmt.Errorf("netstat output has no %q header: %d bytes", netstatHeader, len(payload))
	}
	return false, nil
}

// ProbeSession is the production Probe: it shells ioreg for the console session, then
// netstat for an inbound screen share, and folds both into the snapshot.
func ProbeSession(ctx context.Context) (SessionSnapshot, error) {
	cmd := exec.CommandContext(ctx, ioregArgv[0], ioregArgv[1:]...) //nolint:gosec // G204: ioregArgv is a fixed argv, not user-supplied.
	out, err := cmd.Output()
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("run ioreg: %w", err)
	}
	snapshot, err := parseSession(out)
	if err != nil {
		return SessionSnapshot{}, err
	}
	netCmd := exec.CommandContext(ctx, screenShareArgv[0], screenShareArgv[1:]...) //nolint:gosec // G204: screenShareArgv is a fixed argv, not user-supplied.
	netOut, err := netCmd.Output()
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("run netstat: %w", err)
	}
	shared, err := parseScreenShare(netOut)
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("parse netstat: %w", err)
	}
	snapshot.ScreenShared = shared
	return snapshot, nil
}

// HasActiveSession reports whether a real person is at this host's keyboard right now:
// a GUI session holds the console, its screen is unlocked, and the console user is the
// user this process runs as. A locked screen, a headless box, or another user holding
// the console via fast user switching all return false. A live screen share also returns
// false: when someone is mirroring this host over Screen Sharing we cannot prove a Touch
// ID tap reaches the physically-present human, so the host is treated as NOT locally
// attended and consent routes to a peer instead of prompting here — screen-share wins.
// It mirrors the Python has_active_session.
func HasActiveSession(ctx context.Context, probe Probe) (bool, error) {
	snapshot, err := probe(ctx)
	if err != nil {
		return false, err
	}
	me, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("resolve current user: %w", err)
	}
	return snapshot.OnConsole && !snapshot.Locked && snapshot.ConsoleUser == me.Username && !snapshot.ScreenShared, nil
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
		"on_console":    snapshot.OnConsole,
		"locked":        snapshot.Locked,
		"console_user":  consoleUser,
		"screen_shared": snapshot.ScreenShared,
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
