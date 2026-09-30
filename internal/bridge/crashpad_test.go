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

func TestParseCmdline(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []byte
		want    []string
	}{
		{"a nul-terminated argv", []byte("/bin/sleep\x00600\x00"), []string{"/bin/sleep", "600"}},
		{"an argv with an empty trailing argument", []byte("/bin/sh\x00\x00"), []string{"/bin/sh", ""}},
		{"a zombie or kernel thread", nil, []string{""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCmdline(tc.cmdline); !slices.Equal(got, tc.want) {
				t.Fatalf("parseCmdline(%q) = %q, want %q", tc.cmdline, got, tc.want)
			}
		})
	}
}
