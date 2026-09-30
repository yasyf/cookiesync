package bridge

import (
	"slices"
	"strings"
	"testing"
)

func TestServesCrashpadDatabase(t *testing.T) {
	const session = "/home/u/.config/cookiesync/bridge/sessions/0123456789abcdef"
	database := crashpadDatabase(session)
	if want := session + "/Crashpad"; database != want {
		t.Fatalf("crashpadDatabase(%q) = %q, want %q", session, database, want)
	}
	handler := []string{
		"/opt/google/chrome/chrome_crashpad_handler", "--monitor-self", "--monitor-self-annotation=ptype=crashpad-handler",
		"--database=" + database, "--metrics-dir=" + session, "--url=https://clients2.google.com/cr/report",
		"--annotation=plat=Linux", "--initial-client-fd=5", "--shared-client-connection",
	}
	twin := []string{
		"/opt/google/chrome/chrome_crashpad_handler", "--no-periodic-tasks", "--monitor-self-annotation=ptype=crashpad-handler",
		"--database=" + database, "--url=https://clients2.google.com/cr/report", "--initial-client-fd=6", "--shared-client-connection",
	}
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"the session's handler", handler, true},
		{"the session's --monitor-self twin", twin, true},
		{"any executable serving the session's database", []string{"/bin/sh", "-c", "read line", "double", "--database=" + database}, true},
		{"another session's handler", withDatabase(handler, "/home/u/.config/cookiesync/bridge/sessions/fedcba9876543210/Crashpad"), false},
		{"the default profile's handler", withDatabase(handler, "/home/u/.config/google-chrome/Crash Reports"), false},
		{"a database nested below the session's", withDatabase(handler, database+"/pending"), false},
		{"a database whose path merely starts with the session's", withDatabase(handler, database+"2"), false},
		{"a bare crashpad comm", []string{"chrome_crashpad"}, false},
		{"the handler binary with no database", []string{"/opt/google/chrome/chrome_crashpad_handler", "--monitor-self"}, false},
		{"the database flag as argv[0]", []string{"--database=" + database}, false},
		{"the database path without its flag", []string{"/opt/google/chrome/chrome_crashpad_handler", database}, false},
		{"chrome itself on the session's user-data-dir", []string{"/opt/google/chrome/chrome", "--remote-debugging-pipe", "--user-data-dir=" + session, "--headless=new"}, false},
		{"a chrome child naming the handler pid", []string{"/opt/google/chrome/chrome", "--type=renderer", "--crashpad-handler-pid=4242", "--user-data-dir=" + session}, false},
		{"an empty cmdline", []string{""}, false},
		{"no argv", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := servesCrashpadDatabase(tc.argv, database); got != tc.want {
				t.Fatalf("servesCrashpadDatabase(%q, %q) = %v, want %v", tc.argv, database, got, tc.want)
			}
		})
	}
}

func withDatabase(argv []string, database string) []string {
	swapped := slices.Clone(argv)
	for i, arg := range swapped {
		if strings.HasPrefix(arg, crashpadDatabaseArg) {
			swapped[i] = crashpadDatabaseArg + database
		}
	}
	return swapped
}

func TestVerifyLaunchEvidence(t *testing.T) {
	const nonce = "launch-nonce"
	const another = "another-launch-nonce"
	tests := []struct {
		name    string
		environ string
		want    string
	}{
		{"this launch's entry", "HOME=/home/u\x00COOKIESYNC_BRIDGE_LAUNCH=" + nonce + "\x00PATH=/usr/bin\x00", ""},
		{"this launch's entry as the sole variable", "COOKIESYNC_BRIDGE_LAUNCH=" + nonce + "\x00", ""},
		{"this launch's entry without a trailing nul", "COOKIESYNC_BRIDGE_LAUNCH=" + nonce, ""},
		{"another launch's entry", "COOKIESYNC_BRIDGE_LAUNCH=" + another + "\x00", "its environment carries another launch's COOKIESYNC_BRIDGE_LAUNCH"},
		{"this launch's nonce as a prefix of a longer value", "COOKIESYNC_BRIDGE_LAUNCH=" + nonce + "0\x00", "its environment carries another launch's COOKIESYNC_BRIDGE_LAUNCH"},
		{"an empty entry", "COOKIESYNC_BRIDGE_LAUNCH=\x00", "its environment carries another launch's COOKIESYNC_BRIDGE_LAUNCH"},
		{"this launch's nonce under a longer key", "COOKIESYNC_BRIDGE_LAUNCHER=" + nonce + "\x00", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
		{"this launch's nonce inside another value", "COOKIESYNC_SMOKE_RUN=" + nonce + "\x00", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
		{"this launch's entry inside another value", "X=COOKIESYNC_BRIDGE_LAUNCH=" + nonce + "\x00", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
		{"the key alone", "COOKIESYNC_BRIDGE_LAUNCH\x00", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
		{"no entry", "HOME=/home/u\x00PATH=/usr/bin\x00", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
		{"an empty environment (a zombie or kernel thread)", "", "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if err := verifyLaunchEvidence([]byte(tc.environ), nonce); err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("verifyLaunchEvidence = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerifyHandlerExe(t *testing.T) {
	tests := []struct {
		name string
		exe  string
		want string
	}{
		{"chrome's handler", "/opt/google/chrome/chrome_crashpad_handler", ""},
		{"chromium's handler", "/usr/lib/chromium/chrome_crashpad_handler", ""},
		{"a handler replaced on disk by an update", "/opt/google/chrome/chrome_crashpad_handler (deleted)", "its executable /opt/google/chrome/chrome_crashpad_handler (deleted) is not chrome_crashpad_handler"},
		{"chrome itself", "/opt/google/chrome/chrome", "its executable /opt/google/chrome/chrome is not chrome_crashpad_handler"},
		{"a shell", "/usr/bin/dash", "its executable /usr/bin/dash is not chrome_crashpad_handler"},
		{"a directory named like the handler", "/opt/chrome_crashpad_handler/chrome", "its executable /opt/chrome_crashpad_handler/chrome is not chrome_crashpad_handler"},
		{"a name that merely starts like the handler", "/opt/google/chrome/chrome_crashpad_handler2", "its executable /opt/google/chrome/chrome_crashpad_handler2 is not chrome_crashpad_handler"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if err := verifyHandlerExe(tc.exe); err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("verifyHandlerExe(%q) = %q, want %q", tc.exe, got, tc.want)
			}
		})
	}
}

func TestSplitNUL(t *testing.T) {
	tests := []struct {
		name string
		list []byte
		want []string
	}{
		{"a nul-terminated argv", []byte("/bin/sleep\x00600\x00"), []string{"/bin/sleep", "600"}},
		{"an argv with an empty trailing argument", []byte("/bin/sh\x00\x00"), []string{"/bin/sh", ""}},
		{"a nul-terminated environment", []byte("HOME=/home/u\x00PATH=/usr/bin\x00"), []string{"HOME=/home/u", "PATH=/usr/bin"}},
		{"a zombie or kernel thread", nil, []string{""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitNUL(tc.list); !slices.Equal(got, tc.want) {
				t.Fatalf("splitNUL(%q) = %q, want %q", tc.list, got, tc.want)
			}
		})
	}
}

func TestParseProcStat(t *testing.T) {
	const handler = "8580 (chrome_crashpad) S 1 8579 8579 0 -1 4194560 1234 0 0 0 5 3 0 0 20 0 2 0 123456 12345678 900 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"
	tests := []struct {
		name    string
		stat    string
		want    procStat
		wantErr string
	}{
		{"a crashpad handler", handler, procStat{ppid: 1, pgid: 8579, sid: 8579, start: 123456}, ""},
		{"a comm with spaces and a parenthesis", "42 (a b) c) R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77 0 0 0", procStat{ppid: 7, pgid: 8, sid: 9, start: 77}, ""},
		{"exactly the fields up to the start time", "42 (x) R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77", procStat{ppid: 7, pgid: 8, sid: 9, start: 77}, ""},
		{"no comm", "42 R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77", procStat{}, `bridge: /proc stat "42 R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77" names no comm`},
		{"too few fields", "42 (x) R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0", procStat{}, `bridge: /proc stat "42 (x) R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0" stops before field 22`},
		{"a non-numeric ppid", "42 (x) R p 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77", procStat{}, `bridge: /proc stat ppid: strconv.Atoi: parsing "p": invalid syntax`},
		{"a negative start time", "42 (x) R 7 8 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 -1", procStat{}, `bridge: /proc stat start time: strconv.ParseUint: parsing "-1": invalid syntax`},
		{"an empty file", "", procStat{}, `bridge: /proc stat "" names no comm`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProcStat([]byte(tc.stat))
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if got != tc.want || gotErr != tc.wantErr {
				t.Fatalf("parseProcStat = %+v, %q, want %+v, %q", got, gotErr, tc.want, tc.wantErr)
			}
		})
	}
}
