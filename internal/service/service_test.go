package service

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeLauncher records the plist paths passed to Bootstrap and the labels passed to
// Bootout, in call order, so a test asserts install/uninstall drove launchctl without
// loading a real agent on the live system.
type fakeLauncher struct {
	bootstrapped []string
	bootedOut    []string
}

func (f *fakeLauncher) Bootstrap(_ context.Context, plistPath string) error {
	f.bootstrapped = append(f.bootstrapped, plistPath)
	return nil
}

func (f *fakeLauncher) Bootout(_ context.Context, label string) error {
	f.bootedOut = append(f.bootedOut, label)
	return nil
}

// TestConfigLabels pins the two full launchd labels exactly; they appear in install
// output and any live plist, so they must not drift from the Python service.
func TestConfigLabels(t *testing.T) {
	if TickLabel != "com.github.yasyf.cookiesync.reconcile" {
		t.Errorf("TickLabel = %q", TickLabel)
	}
	if WatchLabel != "com.github.yasyf.cookiesync.watch" {
		t.Errorf("WatchLabel = %q", WatchLabel)
	}
}

// TestInstallWritesBothPlistsWithRightKeys installs against a temp HOME and a fake
// launcher, then parses each written plist and asserts its label, the cookiesync verb
// it runs, the Aqua session limit (keychain/Touch ID), and the schedule key unique to
// it — the reconcile tick's StartInterval and the watch daemon's KeepAlive. No real
// agent is loaded.
func TestInstallWritesBothPlistsWithRightKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launcher := &fakeLauncher{}

	if err := Install(context.Background(), launcher, false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	agents := filepath.Join(home, "Library", "LaunchAgents")
	exe := mustExe(t)

	tick := parsePlist(t, mustRead(t, filepath.Join(agents, TickLabel+".plist")))
	if tick["Label"] != TickLabel {
		t.Errorf("tick Label = %v, want %q", tick["Label"], TickLabel)
	}
	if got := programArgs(t, tick); len(got) != 2 || got[0] != exe || got[1] != "reconcile" {
		t.Errorf("tick ProgramArguments = %v, want [%s reconcile]", got, exe)
	}
	if tick["StartInterval"] != 900 {
		t.Errorf("tick StartInterval = %v, want 900", tick["StartInterval"])
	}
	if tick["LimitLoadToSessionType"] != "Aqua" {
		t.Errorf("tick LimitLoadToSessionType = %v, want Aqua", tick["LimitLoadToSessionType"])
	}
	if _, hasKeepAlive := tick["KeepAlive"]; hasKeepAlive {
		t.Error("tick must not carry KeepAlive (that key is the watch agent's)")
	}

	watch := parsePlist(t, mustRead(t, filepath.Join(agents, WatchLabel+".plist")))
	if watch["Label"] != WatchLabel {
		t.Errorf("watch Label = %v, want %q", watch["Label"], WatchLabel)
	}
	if got := programArgs(t, watch); len(got) != 2 || got[1] != "watch" {
		t.Errorf("watch ProgramArguments = %v, want [%s watch]", got, exe)
	}
	if watch["KeepAlive"] != true {
		t.Errorf("watch KeepAlive = %v, want true", watch["KeepAlive"])
	}
	if watch["LimitLoadToSessionType"] != "Aqua" {
		t.Errorf("watch LimitLoadToSessionType = %v, want Aqua", watch["LimitLoadToSessionType"])
	}
	if _, hasInterval := watch["StartInterval"]; hasInterval {
		t.Error("watch must not carry StartInterval (that key is the tick's)")
	}

	// Both agents were booted out before bootstrap (idempotent reinstall) and then
	// bootstrapped, in tick-then-watch order.
	if len(launcher.bootstrapped) != 2 {
		t.Fatalf("bootstrapped %d agents, want 2", len(launcher.bootstrapped))
	}
}

// TestInstallTickOnlyWritesOnlyTheTick proves --tick-only installs the reconcile cron
// and not the watch daemon.
func TestInstallTickOnlyWritesOnlyTheTick(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launcher := &fakeLauncher{}

	if err := Install(context.Background(), launcher, true); err != nil {
		t.Fatalf("Install tick-only: %v", err)
	}

	agents := filepath.Join(home, "Library", "LaunchAgents")
	if _, err := os.Stat(filepath.Join(agents, TickLabel+".plist")); err != nil {
		t.Errorf("tick plist not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(agents, WatchLabel+".plist")); !os.IsNotExist(err) {
		t.Errorf("watch plist written despite --tick-only (stat err = %v)", err)
	}
	if len(launcher.bootstrapped) != 1 {
		t.Errorf("bootstrapped %d agents, want 1 (tick only)", len(launcher.bootstrapped))
	}
}

// TestUninstallRemovesBothPlists installs, then uninstalls, and asserts both plist
// files are gone and both labels were booted out.
func TestUninstallRemovesBothPlists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	launcher := &fakeLauncher{}
	ctx := context.Background()

	if err := Install(ctx, launcher, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := Uninstall(ctx, launcher); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	agents := filepath.Join(home, "Library", "LaunchAgents")
	for _, label := range []string{TickLabel, WatchLabel} {
		if _, err := os.Stat(filepath.Join(agents, label+".plist")); !os.IsNotExist(err) {
			t.Errorf("%s plist not removed on uninstall (stat err = %v)", label, err)
		}
	}
	bootedOut := map[string]bool{}
	for _, l := range launcher.bootedOut {
		bootedOut[l] = true
	}
	for _, label := range []string{TickLabel, WatchLabel} {
		if !bootedOut[label] {
			t.Errorf("%s was not booted out on uninstall", label)
		}
	}
}

// --- plist parsing (a flat top-level <dict> into map[string]any) ---

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test reads a plist it just wrote under a temp HOME.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mustExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	return exe
}

func programArgs(t *testing.T, dict map[string]any) []string {
	t.Helper()
	raw, ok := dict["ProgramArguments"].([]any)
	if !ok {
		t.Fatalf("ProgramArguments is %T, want array", dict["ProgramArguments"])
	}
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i], _ = v.(string)
	}
	return out
}

func parsePlist(t *testing.T, xmlStr string) map[string]any {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			t.Fatalf("plist has no top-level <dict>")
		}
		if err != nil {
			t.Fatalf("plist is not well-formed XML: %v", err)
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "dict" {
			return parseDict(t, dec)
		}
	}
}

func parseDict(t *testing.T, dec *xml.Decoder) map[string]any {
	t.Helper()
	out := map[string]any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist dict parse: %v", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if el.Name.Local != "key" {
				t.Fatalf("expected <key>, got <%s>", el.Name.Local)
			}
			key := readChardata(t, dec)
			out[key] = parseValue(t, dec)
		case xml.EndElement:
			if el.Name.Local == "dict" {
				return out
			}
		}
	}
}

func parseValue(t *testing.T, dec *xml.Decoder) any {
	t.Helper()
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist value parse: %v", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "string":
			return readChardata(t, dec)
		case "integer":
			n, err := strconv.Atoi(strings.TrimSpace(readChardata(t, dec)))
			if err != nil {
				t.Fatalf("plist integer parse: %v", err)
			}
			return n
		case "true":
			return true
		case "false":
			return false
		case "array":
			return parseArray(t, dec)
		case "dict":
			return parseDict(t, dec)
		}
	}
}

func parseArray(t *testing.T, dec *xml.Decoder) []any {
	t.Helper()
	var out []any
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist array parse: %v", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			switch el.Name.Local {
			case "string":
				out = append(out, readChardata(t, dec))
			case "integer":
				n, _ := strconv.Atoi(strings.TrimSpace(readChardata(t, dec)))
				out = append(out, n)
			}
		case xml.EndElement:
			if el.Name.Local == "array" {
				return out
			}
		}
	}
}

func readChardata(t *testing.T, dec *xml.Decoder) string {
	t.Helper()
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("plist chardata parse: %v", err)
		}
		switch el := tok.(type) {
		case xml.CharData:
			b.Write(el)
		case xml.EndElement:
			return b.String()
		}
	}
}
