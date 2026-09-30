package daemon

import (
	"testing"

	"github.com/yasyf/cookiesync/internal/bridge"
)

func TestWindowModeParam(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   bridge.WindowMode
	}{
		{name: "absent leaves the window to the host", params: map[string]any{}, want: bridge.WindowAuto},
		{name: "mistyped leaves the window to the host", params: map[string]any{"headed": "true"}, want: bridge.WindowAuto},
		{name: "true states headed", params: map[string]any{"headed": true}, want: bridge.WindowHeaded},
		{name: "false states headless", params: map[string]any{"headed": false}, want: bridge.WindowHeadless},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := windowModeParam(tt.params); got != tt.want {
				t.Fatalf("windowModeParam(%v) = %v, want %v", tt.params, got, tt.want)
			}
		})
	}
}
