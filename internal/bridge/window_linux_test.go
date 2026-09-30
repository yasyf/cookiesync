package bridge

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestHasDisplayReadsX11AndWayland(t *testing.T) {
	tests := []struct {
		name    string
		display string
		wayland string
		want    bool
	}{
		{name: "neither", want: false},
		{name: "x11", display: ":0", want: true},
		{name: "wayland", wayland: "wayland-0", want: true},
		{name: "both", display: ":0", wayland: "wayland-0", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DISPLAY", tt.display)
			t.Setenv("WAYLAND_DISPLAY", tt.wayland)
			if got := hasDisplay(); got != tt.want {
				t.Fatalf("hasDisplay() with DISPLAY=%q WAYLAND_DISPLAY=%q = %v, want %v", tt.display, tt.wayland, got, tt.want)
			}
		})
	}
}

func TestResolveHeadedWithoutADisplay(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if headed, err := ResolveHeaded(WindowAuto); err != nil || headed {
		t.Fatalf("ResolveHeaded(auto) with no display = %v, %v, want headless", headed, err)
	}
	if _, err := ResolveHeaded(WindowHeaded); !errors.Is(err, errNoDisplay) {
		t.Fatalf("ResolveHeaded(headed) with no display error = %v, want %v", err, errNoDisplay)
	}
}

func TestChromeEnvironmentForwardsTheDisplayOnlyWhenHeaded(t *testing.T) {
	t.Setenv("DISPLAY", ":7")
	t.Setenv("WAYLAND_DISPLAY", "wayland-7")
	t.Setenv("XAUTHORITY", "/home/u/.Xauthority")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	t.Setenv("XDG_CURRENT_DESKTOP", "GNOME")
	unsetenv(t, launchEnv)
	display := []string{"DISPLAY=:7", "WAYLAND_DISPLAY=wayland-7", "XAUTHORITY=/home/u/.Xauthority", "XDG_RUNTIME_DIR=/run/user/1000"}
	withheld := []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XDG_CURRENT_DESKTOP=GNOME"}

	const dataDir = "/home/u/.config/cookiesync/bridge/sessions/0123456789abcdef"
	const nonce = "launch-nonce"
	const database = "BREAKPAD_DUMP_LOCATION=" + dataDir + "/Crashpad"
	const launch = launchEnv + "=" + nonce

	headed := chromeEnvironment(dataDir, true, nonce)
	headless := chromeEnvironment(dataDir, false, nonce)
	for _, variable := range append(display, database, launch) {
		if !slices.Contains(headed, variable) {
			t.Errorf("headed chrome environment lacks %s", environmentKey(variable))
		}
	}
	for _, variable := range []string{database, launch} {
		if !slices.Contains(headless, variable) {
			t.Errorf("headless chrome environment lacks %s", environmentKey(variable))
		}
	}
	for _, variable := range display {
		if slices.Contains(headless, variable) {
			t.Errorf("headless chrome environment carries %s", environmentKey(variable))
		}
	}
	for _, variable := range withheld {
		if slices.Contains(headed, variable) || slices.Contains(headless, variable) {
			t.Errorf("chrome environment carries %s, which would steer chrome's password store", environmentKey(variable))
		}
	}
	if got, want := environmentKeys(headless), environmentKeys(append(bridgeEnvironment(), database, launch)); !slices.Equal(got, want) {
		t.Errorf("headless chrome environment keys = %v, want the bridge environment's plus the session crash database and launch: %v", got, want)
	}
}

func TestChromeEnvironmentCarriesOnlyThisLaunch(t *testing.T) {
	const dataDir = "/home/u/.config/cookiesync/bridge/sessions/0123456789abcdef"
	const nonce = "launch-nonce"
	tests := []struct {
		name      string
		inherits  bool
		inherited string
	}{
		{name: "no launch in the helper's environment"},
		{name: "a stale launch in the helper's environment", inherits: true, inherited: "stale-launch-nonce"},
		{name: "an empty launch in the helper's environment", inherits: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.inherits {
				t.Setenv(launchEnv, tt.inherited)
			} else {
				unsetenv(t, launchEnv)
			}
			want := []string{launchEnv + "=" + nonce}
			for _, headed := range []bool{true, false} {
				got := slices.DeleteFunc(chromeEnvironment(dataDir, headed, nonce), func(variable string) bool { return !carriesLaunch(variable) })
				if !slices.Equal(got, want) {
					t.Errorf("chrome environment (headed %v) carries %d %s entries, this launch's among them: %v; want exactly this launch's",
						headed, len(got), launchEnv, slices.Contains(got, want[0]))
				}
			}
		})
	}
}

func unsetenv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
}

func environmentKey(variable string) string {
	name, _, _ := strings.Cut(variable, "=")
	return name
}

func environmentKeys(environment []string) []string {
	names := make([]string, len(environment))
	for i, variable := range environment {
		names[i] = environmentKey(variable)
	}
	return names
}
