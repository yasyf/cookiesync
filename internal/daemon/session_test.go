package daemon

import (
	"context"
	"testing"
)

// ioregPlist builds an ioreg-shaped XML plist for one console session, with the given
// root-level locked flag and per-session on-console/locked flags and user name —
// enough of the real Root node's shape to exercise parseSession.
func ioregPlist(rootLocked bool, onConsole, sessionLocked bool, userName string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>IOConsoleLocked</key>
	<` + boolTag(rootLocked) + `/>
	<key>IOConsoleUsers</key>
	<array>
		<dict>
			<key>CGSSessionScreenIsLocked</key>
			<` + boolTag(sessionLocked) + `/>
			<key>kCGSSessionOnConsoleKey</key>
			<` + boolTag(onConsole) + `/>
			<key>kCGSSessionUserIDKey</key>
			<integer>501</integer>
			<key>kCGSSessionUserNameKey</key>
			<string>` + userName + `</string>
		</dict>
	</array>
</dict>
</plist>
`
}

func boolTag(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestParseSessionMatchesIoregShape table-drives parseSession over the real ioreg
// plist shape: an unlocked console session, a screen-locked one (via both the root
// flag and the per-session flag), and a headless box with no on-console session.
func TestParseSessionMatchesIoregShape(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    SessionSnapshot
	}{
		{
			name:    "live unlocked console",
			payload: ioregPlist(false, true, false, "yasyf"),
			want:    SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: "yasyf"},
		},
		{
			name:    "locked via root flag",
			payload: ioregPlist(true, true, false, "yasyf"),
			want:    SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: "yasyf"},
		},
		{
			name:    "locked via per-session flag",
			payload: ioregPlist(false, true, true, "yasyf"),
			want:    SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: "yasyf"},
		},
		{
			name:    "headless: no on-console session",
			payload: ioregPlist(false, false, false, "yasyf"),
			want:    SessionSnapshot{OnConsole: false, Locked: false, ConsoleUser: ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSession([]byte(tc.payload))
			if err != nil {
				t.Fatalf("parseSession: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseSession = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestParseSessionEmptyConsoleUsers proves an empty IOConsoleUsers array (no GUI
// session at all) parses as headless rather than erroring.
func TestParseSessionEmptyConsoleUsers(t *testing.T) {
	payload := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>IOConsoleLocked</key>
	<false/>
	<key>IOConsoleUsers</key>
	<array/>
</dict>
</plist>
`
	got, err := parseSession([]byte(payload))
	if err != nil {
		t.Fatalf("parseSession: %v", err)
	}
	if got != (SessionSnapshot{}) {
		t.Fatalf("empty users = %+v, want zero snapshot", got)
	}
}

// TestSessionSummaryNullsConsoleUserWhenHeadless proves the whoami summary maps an
// absent console user to a JSON null (a nil any), not an empty string.
func TestSessionSummaryNullsConsoleUserWhenHeadless(t *testing.T) {
	got, err := sessionSummary(context.Background(), staticProbe(SessionSnapshot{OnConsole: false}))
	if err != nil {
		t.Fatalf("sessionSummary: %v", err)
	}
	if got["console_user"] != nil {
		t.Fatalf("console_user = %v, want nil", got["console_user"])
	}
}

// TestParseScreenShare table-drives parseScreenShare over real `netstat -anv -p tcp`
// rows. An inbound Screen Sharing session — this host's local address on .5900 in the
// ESTABLISHED state — is the only shape that counts as shared. The always-present *.5900
// LISTEN listener, a busy connection on another port, and a socketless table are all
// "not shared"; a payload with no netstat header at all is malformed.
func TestParseScreenShare(t *testing.T) {
	const header = "Active Internet connections (including servers)\n" +
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes  txbytes  rhiwat  shiwat  process:pid  options  gencnt  flags  flags1 usecnt rtncnt fltrs\n"
	const listen5900 = "tcp46      0      0  *.5900                 *.*                    LISTEN            0            0  131072  131072    screensharingd:912   00100 00000006 00000000000037c9 00000001 00000800      1      0 000000\n"
	const established5900 = "tcp4       0      0  192.168.4.145.5900     192.168.4.50.54873     ESTABLISHED   14832         1083  131072  131600    screensharingd:912   00102 00000008 0000000001fec78d 00000081 04000900      2      0 000000\n"
	const established443 = "tcp4       0      0  192.168.4.145.55531    35.190.46.17.443       ESTABLISHED   3010          839  131072  131600          2.1.198:60299  00102 00000008 00000000021a4621 00000081 04000900      2      0 000000\n"

	tests := []struct {
		name    string
		payload string
		want    bool
		wantErr bool
	}{
		{
			name:    "inbound established screen share on .5900",
			payload: header + listen5900 + established443 + established5900,
			want:    true,
		},
		{
			name:    "listen-only on *.5900 is the idle listener",
			payload: header + listen5900 + established443,
			want:    false,
		},
		{
			name:    "established on a non-5900 local port",
			payload: header + established443,
			want:    false,
		},
		{
			name:    "socketless table",
			payload: header,
			want:    false,
		},
		{
			name:    "malformed payload with no netstat header",
			payload: "this is not netstat output\n",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseScreenShare([]byte(tc.payload))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseScreenShare = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScreenShare: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseScreenShare = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHasActiveSessionScreenShareWins proves a live screen share makes HasActiveSession
// return false even when the console is held, unlocked, and owned by this user — we
// cannot prove a Touch ID tap reaches the physically-present human, so the host is not
// locally attended and consent must route to a peer.
func TestHasActiveSessionScreenShareWins(t *testing.T) {
	me := currentUser(t)

	attended := liveSession(me)
	live, err := HasActiveSession(context.Background(), staticProbe(attended))
	if err != nil {
		t.Fatalf("HasActiveSession: %v", err)
	}
	if !live {
		t.Fatalf("an unlocked console owned by this user must be a live session")
	}

	shared := attended
	shared.ScreenShared = true
	live, err = HasActiveSession(context.Background(), staticProbe(shared))
	if err != nil {
		t.Fatalf("HasActiveSession: %v", err)
	}
	if live {
		t.Fatalf("a screen-shared host must NOT be a live local session (screen-share wins)")
	}
}

// TestKeybagLocked proves keybagLocked scopes to the daemon user's own unlocked console:
// an attended session is available, but a locked screen, a console held by another user via
// fast user switching, and a session-absent box are all keybag-locked. Unlike
// HasActiveSession it ignores ScreenShared — a mirrored unlocked session still decrypts.
func TestKeybagLocked(t *testing.T) {
	me := currentUser(t)
	attendedShared := liveSession(me)
	attendedShared.ScreenShared = true

	tests := []struct {
		name string
		snap SessionSnapshot
		want bool
	}{
		{"attended", liveSession(me), false},
		{"attended while screen-shared", attendedShared, false},
		{"locked screen", SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: me}, true},
		{"another user via fast user switching", SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: me + "-other"}, true},
		{"session absent", SessionSnapshot{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keybagLocked(tc.snap)
			if err != nil {
				t.Fatalf("keybagLocked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("keybagLocked(%+v) = %v, want %v", tc.snap, got, tc.want)
			}
		})
	}
}
