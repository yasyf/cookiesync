package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

func readStateEnvelope(t *testing.T) map[string]any {
	t.Helper()
	path, err := paths.Config.Path()
	if err != nil {
		t.Fatalf("state path: %v", err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is the test-controlled state.json under a temp config home.
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return envelope
}

func writeStateEnvelope(t *testing.T, envelope map[string]any) {
	t.Helper()
	path, err := paths.Config.Path()
	if err != nil {
		t.Fatalf("state path: %v", err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

func stateSettings(envelope map[string]any) map[string]any {
	return envelope["cookie_sync"].(map[string]any)["settings"].(map[string]any)
}

func seedPreReleaseState(t *testing.T) map[string]any {
	t.Helper()
	if err := state.New(paths.Config).Initialize(context.Background()); err != nil {
		t.Fatalf("initialize state: %v", err)
	}
	envelope := readStateEnvelope(t)
	stateSettings(envelope)["watch_debounce"] = "3s"
	stateSettings(envelope)["auth_ttl"] = "2h"
	envelope["cookie_sync"].(map[string]any)["consent_route_to"] = "me@desk"
	writeStateEnvelope(t, envelope)
	return readStateEnvelope(t)
}

func runSettingsCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := newRoot("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"settings"}, args...))
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestSettingsWatchDebounceWritesOnlyTheSetting(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	before := seedPreReleaseState(t)

	out, err := runSettingsCmd(t, "watch-debounce", "10s")
	if err != nil {
		t.Fatalf("settings watch-debounce 10s: %v\n%s", err, out)
	}
	if want := "Stored watch debounce 10s in state.json.\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
	after := readStateEnvelope(t)
	if got := stateSettings(after)["watch_debounce"]; got != "10s" {
		t.Fatalf("watch_debounce = %v, want 10s", got)
	}
	stateSettings(before)["watch_debounce"] = "10s"
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("state = %v, want %v with only watch_debounce changed", after, before)
	}
}

func TestSettingsWatchDebounceRefusesInvalidDurations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "zero", args: []string{"0s"}, wantErr: "watch debounce 0s must be positive"},
		{name: "negative", args: []string{"--", "-5s"}, wantErr: "watch debounce -5s must be positive"},
		{name: "missing unit", args: []string{"10"}, wantErr: `invalid duration unit in "10" (want h, m, or s)`},
		{name: "fractional", args: []string{"1.5s"}, wantErr: `invalid duration "1.5s": strconv.Atoi: parsing "1.5": invalid syntax`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutil.IsolateHostConfig(t, paths.Config)
			before := seedPreReleaseState(t)

			_, err := runSettingsCmd(t, append([]string{"watch-debounce"}, tc.args...)...)
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("settings watch-debounce %v error = %v, want %q", tc.args, err, tc.wantErr)
			}
			if after := readStateEnvelope(t); !reflect.DeepEqual(after, before) {
				t.Fatalf("state = %v, want it unchanged at %v", after, before)
			}
		})
	}
}
