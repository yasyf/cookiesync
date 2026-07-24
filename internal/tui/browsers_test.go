package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
	stui "github.com/yasyf/synckit/tui"
)

// fakeRunner is a hostregistry.Runner stand-in for the add flow's remote profile
// enumeration: SSH returns canned output (or an error) for a target, recording the
// remoteCmd it was asked to run. Local is never exercised by the Browsers screen.
type fakeRunner struct {
	ssh     map[string]string
	sshErr  map[string]error
	lastCmd string
}

func (r *fakeRunner) Local(_ context.Context, _ string, _ ...string) (string, error) {
	return "", fmt.Errorf("fakeRunner.Local must not be called")
}

func (r *fakeRunner) SSH(_ context.Context, target, remoteCmd string) (string, error) {
	r.lastCmd = remoteCmd
	if err, ok := r.sshErr[target]; ok {
		return "", err
	}
	return r.ssh[target], nil
}

// seedMesh writes a shared synckit host registry under a temp XDG_CONFIG_HOME so
// the screen's load resolves a known mesh (self plus peers) and reads an empty
// cookiesync state from the same root. hostregistry.Mesh keys off
// XDG_CONFIG_HOME, isolating each test.
func seedMesh(t *testing.T, self string, hosts ...string) {
	t.Helper()
	if hosts == nil {
		hosts = []string{}
	}
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if err := hostregistry.Mesh.InitializeState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		fact, err := hostregistry.NewSSHHostFact(host, "/usr/local/bin/synckitd", []string{host})
		if err != nil {
			t.Fatal(err)
		}
		if err := hostregistry.Mesh.RegisterHost(context.Background(), fact); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hostregistry.Mesh.Update(context.Background(), func(g *hostregistry.Registry) error { g.Self = self; g.Hosts = hosts; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := state.New(paths.Config).Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// screenHarness adapts a tui.Screen to a tea.Model so teatest can drive the
// Browsers screen on its own, standing in for the synckit router. It mirrors the
// router's one router-level concern the screen relies on: ctrl-c quits unless the
// screen wants the key for a modal sub-state.
type screenHarness struct{ s stui.Screen }

func (h screenHarness) Init() tea.Cmd { return h.s.Init() }

func (h screenHarness) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.Type == tea.KeyCtrlC && !h.s.WantsKey(k) {
		return h, tea.Quit
	}
	s, cmd := h.s.Update(msg)
	h.s = s
	return h, cmd
}

func (h screenHarness) View() string { return h.s.View() }

func waitForContent(t *testing.T, tm *teatest.TestModel, substrs ...string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		for _, s := range substrs {
			if !bytes.Contains(b, []byte(s)) {
				return false
			}
		}
		return true
	}, teatest.WithDuration(5*time.Second), teatest.WithCheckInterval(20*time.Millisecond))
}

// TestBrowsersEmptyStateAndAddPicker proves the screen loads against a seeded
// mesh, lands on its empty state, and that "+" opens the staged add picker at the
// host step listing self first.
func TestBrowsersEmptyStateAndAddPicker(t *testing.T) {
	seedMesh(t, "me@laptop", "you@desktop")
	tm := teatest.NewTestModel(t, screenHarness{s: newBrowsersModel(&fakeRunner{})}, teatest.WithInitialTermSize(100, 30))

	waitForContent(t, tm, "No tracked browsers")

	// "+" opens the host-pick step, which heads with the prompt and lists self.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'+'}})
	waitForContent(t, tm, "pick a host", "me@laptop")

	// esc backs out to the empty state.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitForContent(t, tm, "No tracked browsers")

	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
}

// TestStartAddOpensHostPickerSelfFirst proves startAdd opens the host step seeded
// with self first, then the peers, so the most common choice leads.
func TestStartAddOpensHostPickerSelfFirst(t *testing.T) {
	m := newBrowsersModel(&fakeRunner{})
	m.self = "me@laptop"
	m.hosts = []string{"a@one", "b@two"}

	s, _ := m.startAdd()
	bm := s.(*browsersModel)
	if bm.pick == nil || bm.pick.step != pickHost {
		t.Fatalf("startAdd did not open the host pick step: %+v", bm.pick)
	}
	items := bm.pick.list.Items()
	if len(items) != 3 {
		t.Fatalf("host picker has %d items, want 3 (self + 2 peers)", len(items))
	}
	if got := items[0].(pickItem).value; got != "me@laptop" {
		t.Fatalf("first host = %q, want me@laptop (self leads)", got)
	}
}

// TestWantsKeyGatesModalStates proves the screen swallows keys only while a modal
// sub-state is open, so the router's global tab/quit keys leak through otherwise.
func TestWantsKeyGatesModalStates(t *testing.T) {
	m := newBrowsersModel(&fakeRunner{})
	m.self = "me@laptop"
	if m.WantsKey(tea.KeyMsg{}) {
		t.Fatal("idle screen wants keys, want false")
	}
	s, _ := m.startAdd()
	if !s.(*browsersModel).WantsKey(tea.KeyMsg{}) {
		t.Fatal("screen with open picker does not want keys, want true")
	}
}

// TestRemoveConfirmThenRemove proves r on a selected endpoint opens a confirm,
// and y issues the remove command for that endpoint.
func TestRemoveConfirmThenRemove(t *testing.T) {
	seedMesh(t, "me@laptop")
	m := newBrowsersModel(&fakeRunner{})
	m.loading = false
	ep := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	m.allItems = newBrowserItems([]endpointStatus{{endpoint: ep, present: true}})
	m.refresh()

	s, _ := m.startRemove()
	bm := s.(*browsersModel)
	if bm.confirm == nil || bm.confirm.endpoint != ep {
		t.Fatalf("startRemove did not stage a confirm for the selected endpoint: %+v", bm.confirm)
	}

	s, cmd := bm.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if s.(*browsersModel).confirm != nil {
		t.Fatal("confirm still open after y, want cleared")
	}
	if cmd == nil {
		t.Fatal("y on confirm issued no remove command")
	}
	msg := cmd()
	mut, ok := msg.(browserMutatedMsg)
	if !ok || mut.endpoint != ep || mut.verb != "untracked" {
		t.Fatalf("remove command msg = %+v, want untracked %v", msg, ep)
	}
}

// TestBrowserItemFilterValue pins the filter key shape to host/browser/profile so
// the shared FilterItems narrows on any of the three.
func TestBrowserItemFilterValue(t *testing.T) {
	it := browserItem{endpoint: state.Endpoint{Host: "me@laptop", Browser: "arc", Profile: "Work"}}
	if got := it.FilterValue(); got != "me@laptop/arc/Work" {
		t.Fatalf("FilterValue = %q, want me@laptop/arc/Work", got)
	}
}

// TestProfileItems proves the profile picker renders identity (display name as the
// label, email as the detail) while the selected value stays the on-disk
// directory, and that an empty name falls back to the directory. The dir is what
// keys the cookie store and gets written to state, so it must never be the name.
func TestProfileItems(t *testing.T) {
	profiles := []cookie.Profile{
		{Dir: "Profile 3", Name: "Gmail", Email: "yasyfm@gmail.com"},
		{Dir: "Default", Name: "Yasyf", Email: ""},
		{Dir: "Profile 7", Name: "", Email: ""},
	}
	items := profileItems(profiles)
	want := []pickItem{
		{label: "Gmail", detail: "yasyfm@gmail.com", filter: "Gmail yasyfm@gmail.com Profile 3", value: "Profile 3"},
		{label: "Yasyf", detail: "", filter: "Yasyf  Default", value: "Default"},
		{label: "Profile 7", detail: "", filter: "Profile 7  Profile 7", value: "Profile 7"},
	}
	if len(items) != len(want) {
		t.Fatalf("profileItems returned %d items, want %d", len(items), len(want))
	}
	for i, w := range want {
		got := items[i].(pickItem)
		if got != w {
			t.Fatalf("profileItems[%d] = %#v, want %#v", i, got, w)
		}
		if got.value != profiles[i].Dir {
			t.Fatalf("profileItems[%d].value = %q, want dir %q", i, got.value, profiles[i].Dir)
		}
	}
}

// browserPickModel returns a model parked at the browser step of the add picker,
// with chrome selected, so a single advancePick descends to the profile step.
func browserPickModel(t *testing.T, runner *fakeRunner, self, host string) *browsersModel {
	t.Helper()
	m := newBrowsersModel(runner)
	m.loading = false
	m.self = self
	m.pick = &pickState{
		step: pickBrowser,
		host: host,
		list: newPickList(pickItems([]string{"chrome"}), 80, 20),
	}
	return m
}

// TestRemoteProfileStepEnumeratesOverSSH proves that picking a browser when the
// host is a remote peer issues an ssh enumeration of that host's profiles, parses
// the JSON the `browser profiles` command emits, and populates the profile picker
// from it — with the stored value staying the on-disk directory, never the display
// name. It also pins the remote command shape.
func TestRemoteProfileStepEnumeratesOverSSH(t *testing.T) {
	remote := []cookie.Profile{
		{Dir: "Default", Name: "Yasyf", Email: "yasyf@example.com"},
		{Dir: "Profile 2", Name: "Gmail", Email: "yasyfm@gmail.com"},
	}
	payload, err := json.Marshal(remote)
	if err != nil {
		t.Fatalf("marshal remote profiles: %v", err)
	}
	runner := &fakeRunner{ssh: map[string]string{"you@desktop": string(payload)}}
	m := browserPickModel(t, runner, "me@laptop", "you@desktop")

	// Pick chrome on the remote host: the step turns to profile and goes loading,
	// returning a command that performs the ssh enumeration.
	s, cmd := m.advancePick()
	bm := s.(*browsersModel)
	if bm.pick == nil || bm.pick.step != pickProfile {
		t.Fatalf("advancePick on remote host did not enter the profile step: %+v", bm.pick)
	}
	if !bm.pick.loading {
		t.Fatal("remote profile step is not loading, want loading while ssh is in flight")
	}
	if cmd == nil {
		t.Fatal("remote profile step issued no enumeration command")
	}

	// The loading view names the browser and host.
	if view := bm.View(); !contains(view, "loading chrome profiles from you@desktop") {
		t.Fatalf("loading view = %q, want loading chrome profiles from you@desktop", view)
	}

	// Draining the batched command yields the spinner tick and the profiles message;
	// feed the profiles message back and assert the picker is populated from it.
	msg := drainProfilesMsg(t, cmd)
	if msg.err != nil {
		t.Fatalf("enumeration command errored: %v", msg.err)
	}
	if runner.lastCmd != "cookiesync browser profiles chrome --json" {
		t.Fatalf("remote command = %q, want cookiesync browser profiles chrome --json", runner.lastCmd)
	}

	s, _ = bm.Update(msg)
	bm = s.(*browsersModel)
	if bm.pick.loading {
		t.Fatal("profile step still loading after profiles delivered")
	}
	items := bm.pick.list.Items()
	if len(items) != len(remote) {
		t.Fatalf("profile picker has %d items, want %d from the remote scan", len(items), len(remote))
	}
	for i, want := range remote {
		it := items[i].(pickItem)
		if it.value != want.Dir {
			t.Fatalf("profile[%d].value = %q, want dir %q (stored value must be the dir)", i, it.value, want.Dir)
		}
		if it.label != want.Name || it.detail != want.Email {
			t.Fatalf("profile[%d] label/detail = %q/%q, want %q/%q", i, it.label, it.detail, want.Name, want.Email)
		}
	}
}

// TestRemoteProfileStepSurfacesSSHError proves an ssh failure during enumeration
// lands in the picker as an error the user can esc out of, rather than aborting the
// whole add flow.
func TestRemoteProfileStepSurfacesSSHError(t *testing.T) {
	runner := &fakeRunner{sshErr: map[string]error{"you@desktop": fmt.Errorf("connection refused")}}
	m := browserPickModel(t, runner, "me@laptop", "you@desktop")

	_, cmd := m.advancePick()
	msg := drainProfilesMsg(t, cmd)
	if msg.err == nil {
		t.Fatal("ssh failure produced no error message")
	}

	s, _ := m.Update(msg)
	bm := s.(*browsersModel)
	if bm.pick == nil || bm.pick.loadErr == nil {
		t.Fatalf("ssh error did not land in the picker: %+v", bm.pick)
	}
	if bm.pick.loading {
		t.Fatal("picker still loading after ssh error")
	}
	if view := bm.View(); !contains(view, "connection refused") {
		t.Fatalf("error view = %q, want it to surface connection refused", view)
	}
}

// TestSelfProfileStepUsesLocalScan proves that when the chosen host is self the
// profile step runs the synchronous local scan (no ssh) and populates the picker
// from this host's data root.
func TestSelfProfileStepUsesLocalScan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataRoot := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	seedLocalChrome(t, dataRoot)

	runner := &fakeRunner{} // SSH must not be called on the self path.
	m := browserPickModel(t, runner, "me@laptop", "me@laptop")

	s, cmd := m.advancePick()
	bm := s.(*browsersModel)
	if bm.pick == nil || bm.pick.step != pickProfile {
		t.Fatalf("advancePick on self did not enter the profile step: %+v", bm.pick)
	}
	if bm.pick.loading {
		t.Fatal("self profile step is loading, want a synchronous local scan")
	}
	if cmd != nil {
		if msg := cmd(); msg != nil {
			t.Fatalf("self profile step issued a command yielding %T, want none", msg)
		}
	}
	if runner.lastCmd != "" {
		t.Fatalf("self path issued ssh command %q, want none", runner.lastCmd)
	}
	items := bm.pick.list.Items()
	if len(items) != 1 {
		t.Fatalf("self profile picker has %d items, want 1 (seeded Default)", len(items))
	}
	it := items[0].(pickItem)
	if it.value != "Default" || it.label != "Yasyf" || it.detail != "yasyf@example.com" {
		t.Fatalf("self profile = value %q label %q detail %q, want Default/Yasyf/yasyf@example.com", it.value, it.label, it.detail)
	}
}

// drainProfilesMsg runs a (possibly batched) command and returns the single
// profilesLoadedMsg it produces, ignoring spinner ticks.
func drainProfilesMsg(t *testing.T, cmd tea.Cmd) profilesLoadedMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("nil command, want one producing a profilesLoadedMsg")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			if pm, ok := c().(profilesLoadedMsg); ok {
				return pm
			}
		}
		t.Fatal("batch produced no profilesLoadedMsg")
	}
	pm, ok := msg.(profilesLoadedMsg)
	if !ok {
		t.Fatalf("command produced %T, want profilesLoadedMsg", msg)
	}
	return pm
}

// seedLocalChrome writes a minimal Chrome data root with one Default profile that
// holds a cookie store and an info_cache entry, so the local scan returns it.
func seedLocalChrome(t *testing.T, dataRoot string) {
	t.Helper()
	profileDir := filepath.Join(dataRoot, "Default")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Cookies"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write Cookies: %v", err)
	}
	localState := `{"profile":{"info_cache":{"Default":{"name":"Yasyf","user_name":"yasyf@example.com"}}}}`
	if err := os.WriteFile(filepath.Join(dataRoot, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}
}

// contains reports whether s holds sub, a tiny helper for view assertions.
func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
