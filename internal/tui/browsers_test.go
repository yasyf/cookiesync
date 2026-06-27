package tui

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/yasyf/cookiesync/internal/state"
	stui "github.com/yasyf/synckit/tui"
)

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
	dir := filepath.Join(xdg, "synckit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir synckit: %v", err)
	}
	payload, err := json.Marshal(struct {
		Self  string   `json:"self"`
		Hosts []string `json:"hosts"`
	}{self, hosts})
	if err != nil {
		t.Fatalf("marshal mesh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write mesh state: %v", err)
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
	tm := teatest.NewTestModel(t, screenHarness{s: newBrowsersModel()}, teatest.WithInitialTermSize(100, 30))

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
	m := newBrowsersModel()
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
	m := newBrowsersModel()
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
	m := newBrowsersModel()
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
