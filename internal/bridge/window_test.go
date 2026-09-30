package bridge

import (
	"errors"
	"testing"
)

func TestResolveHeadedDecisionTable(t *testing.T) {
	tests := []struct {
		name       string
		mode       WindowMode
		display    bool
		wantHeaded bool
		wantErr    error
	}{
		{name: "auto with a display runs headed", mode: WindowAuto, display: true, wantHeaded: true},
		{name: "auto without a display runs headless", mode: WindowAuto, display: false, wantHeaded: false},
		{name: "headed with a display runs headed", mode: WindowHeaded, display: true, wantHeaded: true},
		{name: "headed without a display is refused", mode: WindowHeaded, display: false, wantErr: errNoDisplay},
		{name: "headless with a display runs headless", mode: WindowHeadless, display: true, wantHeaded: false},
		{name: "headless without a display runs headless", mode: WindowHeadless, display: false, wantHeaded: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headed, err := resolveHeaded(tt.mode, tt.display)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("resolveHeaded(%v, display=%v) error = %v, want %v", tt.mode, tt.display, err, tt.wantErr)
			}
			if headed != tt.wantHeaded {
				t.Fatalf("resolveHeaded(%v, display=%v) = %v, want %v", tt.mode, tt.display, headed, tt.wantHeaded)
			}
		})
	}
}

func TestChromeArgsHeadlessFlagFollowsTheResolvedWindow(t *testing.T) {
	const dataDir = "/data/session"
	base := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--no-startup-window",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-component-update",
	}
	tests := []struct {
		name   string
		headed bool
		want   []string
	}{
		{name: "headed", headed: true, want: base},
		{name: "headless", headed: false, want: append(append([]string{}, base...), "--headless=new")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chromeArgs(dataDir, tt.headed)
			if len(got) != len(tt.want) {
				t.Fatalf("chromeArgs(headed=%v) = %q, want %q", tt.headed, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("chromeArgs(headed=%v) = %q, want %q", tt.headed, got, tt.want)
				}
			}
		})
	}
}
