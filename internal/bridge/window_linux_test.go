package bridge

import (
	"errors"
	"slices"
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
	display := []string{"DISPLAY=:7", "WAYLAND_DISPLAY=wayland-7", "XAUTHORITY=/home/u/.Xauthority", "XDG_RUNTIME_DIR=/run/user/1000"}
	withheld := []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XDG_CURRENT_DESKTOP=GNOME"}

	const dataDir = "/home/u/.config/cookiesync/bridge/sessions/0123456789abcdef"
	const nonce = "launch-nonce"
	const database = "BREAKPAD_DUMP_LOCATION=" + dataDir + "/Crashpad"
	const launch = "COOKIESYNC_BRIDGE_LAUNCH=" + nonce

	headed := chromeEnvironment(dataDir, true, nonce)
	for _, variable := range append(display, database, launch) {
		if !slices.Contains(headed, variable) {
			t.Errorf("headed chrome environment lacks %q: %q", variable, headed)
		}
	}
	headless := chromeEnvironment(dataDir, false, nonce)
	for _, variable := range display {
		if slices.Contains(headless, variable) {
			t.Errorf("headless chrome environment carries %q: %q", variable, headless)
		}
	}
	for _, variable := range withheld {
		if slices.Contains(headed, variable) || slices.Contains(headless, variable) {
			t.Errorf("chrome environment carries %q, which would steer chrome's password store", variable)
		}
	}
	if bridge := append(bridgeEnvironment(), database, launch); !slices.Equal(bridge, headless) {
		t.Errorf("headless chrome environment = %q, want the bridge environment plus the session crash database and launch %q", headless, bridge)
	}
}
