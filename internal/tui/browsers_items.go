package tui

import (
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/yasyf/cookiesync/internal/state"
	stui "github.com/yasyf/synckit/tui"
)

// browserItem is one tracked endpoint row: the endpoint plus whether its profile
// directory is present on this host.
type browserItem struct {
	endpoint state.Endpoint
	present  bool
}

// FilterValue narrows on the host, browser, and profile together.
func (i browserItem) FilterValue() string {
	return i.endpoint.Host + "/" + i.endpoint.Browser + "/" + i.endpoint.Profile
}

func newBrowserItems(statuses []endpointStatus) []list.Item {
	items := make([]list.Item, len(statuses))
	for i, s := range statuses {
		items[i] = browserItem(s)
	}
	return items
}

// browserDelegate renders a browserItem: a presence glyph, the browser, the
// profile, and the host.
type browserDelegate struct{}

func (browserDelegate) Height() int                         { return 1 }
func (browserDelegate) Spacing() int                        { return 0 }
func (browserDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d browserDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	it := item.(browserItem)

	glyph := stui.BadgeClean.Render("●")
	if !it.present {
		glyph = stui.Dim.Render("○")
	}

	row := glyph + " " + stui.BadgeKind.Render(it.endpoint.Browser) + " " + it.endpoint.Profile + "  " + stui.Dim.Render(it.endpoint.Host)
	if index == m.Index() {
		row = "> " + row
	} else {
		row = "  " + row
	}
	_, _ = io.WriteString(w, lipgloss.NewStyle().MaxWidth(m.Width()).Render(row))
}

// renderBrowserDetail describes the selected endpoint for the detail pane: its
// host, browser, profile, and whether the profile directory is present.
func renderBrowserDetail(item list.Item) string {
	it, ok := item.(browserItem)
	if !ok {
		return stui.Dim.Render("No browser selected.")
	}

	status := stui.BadgeDirty.Render("absent")
	if it.present {
		status = stui.BadgeClean.Render("present")
	}

	lines := []string{
		stui.DetailTitle.Render(string(it.endpoint.ID())),
		"",
		stui.DetailKey.Render("host    ") + it.endpoint.Host,
		stui.DetailKey.Render("browser ") + stui.BadgeKind.Render(it.endpoint.Browser),
		stui.DetailKey.Render("profile ") + it.endpoint.Profile,
		stui.DetailKey.Render("status  ") + status,
	}
	return strings.Join(lines, "\n")
}

// pickItem is one row of the staged add picker — a label and the value it
// resolves to (a host target, a browser name, or a profile dir name).
type pickItem struct {
	label string
	value string
}

func (i pickItem) FilterValue() string { return i.label }

// pickDelegate renders a pickItem as a single accented label row.
type pickDelegate struct{}

func (pickDelegate) Height() int                         { return 1 }
func (pickDelegate) Spacing() int                        { return 0 }
func (pickDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (d pickDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	it := item.(pickItem)
	row := "  " + it.label
	if index == m.Index() {
		row = stui.Accent.Render("> ") + it.label
	}
	_, _ = io.WriteString(w, lipgloss.NewStyle().MaxWidth(m.Width()).Render(row))
}

func pickItems(labels []string) []list.Item {
	items := make([]list.Item, len(labels))
	for i, l := range labels {
		items[i] = pickItem{label: l, value: l}
	}
	return items
}
