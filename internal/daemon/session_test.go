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
