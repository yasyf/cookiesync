package tui

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	stui "github.com/yasyf/synckit/tui"
)

// pickStep is which stage of the staged add picker is open, or pickNone when the
// screen is showing its endpoint list.
type pickStep int

const (
	pickNone pickStep = iota
	pickHost
	pickBrowser
	pickProfile
)

// browsersReserve is the rows the screen keeps below the master-detail split for
// its status line.
const browsersReserve = 1

// confirmState is an open removal confirmation awaiting its endpoint.
type confirmState struct {
	prompt   string
	endpoint state.Endpoint
}

// pickState accumulates the staged add picker's choices as the user descends
// host → browser → profile.
type pickState struct {
	step    pickStep
	list    list.Model
	host    string
	browser string
}

type browsersModel struct {
	list     list.Model
	allItems []list.Item
	filter   stui.FilterBar
	loading  bool
	spin     spinner.Model
	self     string
	hosts    []string
	pick     *pickState
	confirm  *confirmState
	status   string
	keys     browsersKeyMap

	mdListW      int
	mdDetailW    int
	mdHeight     int
	mdShowDetail bool
}

func newBrowsersModel() *browsersModel {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	l := list.New(nil, browserDelegate{}, 0, 0)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()
	return &browsersModel{list: l, filter: stui.NewFilterBar(), loading: true, spin: sp, keys: newBrowsersKeyMap()}
}

func (m *browsersModel) Title() string { return "Browsers" }

func (m *browsersModel) Help() []key.Binding {
	if m.pick != nil {
		return []key.Binding{m.keys.Pick, m.keys.Cancel}
	}
	if m.confirm != nil {
		return []key.Binding{m.keys.Confirm, m.keys.Cancel}
	}
	return []key.Binding{m.keys.Filter, m.keys.Add, m.keys.Remove}
}

// WantsKey swallows keys whenever a modal sub-state is open — the add picker, a
// removal confirmation, or a focused filter — so the router's global tab/quit
// keys do not leak into them.
func (m *browsersModel) WantsKey(tea.KeyMsg) bool {
	return m.pick != nil || m.confirm != nil || m.filter.Focused()
}

func (m *browsersModel) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, loadBrowsersCmd())
}

func (m *browsersModel) Update(msg tea.Msg) (stui.Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.mdListW, m.mdDetailW, m.mdHeight, m.mdShowDetail = stui.SplitDims(msg.Width, msg.Height-stui.FilterBarLines-browsersReserve)
		m.list.SetSize(m.mdListW, m.mdHeight)
		if m.pick != nil {
			m.pick.list.SetSize(m.mdListW, m.mdHeight)
		}
		return m, nil

	case browsersLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.status = stui.StatusErr.Render(msg.err.Error())
			return m, nil
		}
		m.self = msg.self
		m.hosts = msg.peers
		m.allItems = newBrowserItems(msg.endpoints)
		cmd := m.refresh()
		return m, cmd

	case browserMutatedMsg:
		if msg.err != nil {
			m.status = stui.StatusErr.Render(msg.verb + " failed: " + msg.err.Error())
			return m, nil
		}
		m.status = stui.StatusOK.Render(msg.verb + " " + string(msg.endpoint.ID()))
		return m, loadBrowsersCmd()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		if m.loading {
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *browsersModel) handleKey(msg tea.KeyMsg) (stui.Screen, tea.Cmd) {
	if m.pick != nil {
		return m.handlePickKey(msg)
	}

	if m.confirm != nil {
		switch {
		case key.Matches(msg, m.keys.Confirm):
			ep := m.confirm.endpoint
			m.confirm = nil
			return m, removeBrowserCmd(ep)
		case key.Matches(msg, m.keys.Cancel):
			m.confirm = nil
			return m, nil
		}
		return m, nil
	}

	if m.filter.Focused() {
		return m.handleFilterKey(msg)
	}

	switch {
	case key.Matches(msg, m.keys.Filter):
		cmd := m.filter.Focus()
		return m, cmd
	case key.Matches(msg, m.keys.Add):
		return m.startAdd()
	case key.Matches(msg, m.keys.Remove):
		return m.startRemove()
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// handleFilterKey routes keys while the filter bar holds focus: esc clears and
// blurs, enter blurs keeping the filter, anything else edits the query and
// re-narrows the list live.
func (m *browsersModel) handleFilterKey(msg tea.KeyMsg) (stui.Screen, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.filter.Blur()
		m.filter.Clear()
		cmd := m.refresh()
		return m, cmd
	case tea.KeyEnter:
		m.filter.Blur()
		return m, nil
	}
	var icmd tea.Cmd
	m.filter, icmd = m.filter.Update(msg)
	rcmd := m.refresh()
	return m, tea.Batch(icmd, rcmd)
}

// refresh recomputes the visible list from the canonical slice under the active
// filter, keeping the cursor on the same endpoint.
func (m *browsersModel) refresh() tea.Cmd {
	sel := selectedID(m.list)
	visible := stui.FilterItems(m.allItems, m.filter.Value())
	cmd := m.list.SetItems(visible)
	selectID(&m.list, sel)
	return cmd
}

func (m *browsersModel) startRemove() (stui.Screen, tea.Cmd) {
	it, ok := m.list.SelectedItem().(browserItem)
	if !ok {
		return m, nil
	}
	m.confirm = &confirmState{
		prompt:   fmt.Sprintf("Stop tracking %s? (y/N)", it.endpoint.ID()),
		endpoint: it.endpoint,
	}
	return m, nil
}

// startAdd opens the staged picker at its host step, seeding it with the mesh
// (self first, then peers) resolved at load.
func (m *browsersModel) startAdd() (stui.Screen, tea.Cmd) {
	if m.self == "" {
		m.status = stui.StatusErr.Render("no mesh host resolved")
		return m, nil
	}
	hosts := append([]string{m.self}, m.hosts...)
	m.pick = &pickState{step: pickHost, list: newPickList(pickItems(hosts), m.mdListW, m.mdHeight)}
	return m, nil
}

func (m *browsersModel) handlePickKey(msg tea.KeyMsg) (stui.Screen, tea.Cmd) {
	if key.Matches(msg, m.keys.Cancel) {
		m.pick = nil
		return m, nil
	}
	if key.Matches(msg, m.keys.Pick) {
		return m.advancePick()
	}
	var cmd tea.Cmd
	m.pick.list, cmd = m.pick.list.Update(msg)
	return m, cmd
}

// advancePick consumes the current picker selection and either descends to the
// next step or, at the profile step, writes the endpoint.
func (m *browsersModel) advancePick() (stui.Screen, tea.Cmd) {
	it, ok := m.pick.list.SelectedItem().(pickItem)
	if !ok {
		return m, nil
	}
	switch m.pick.step {
	case pickHost:
		m.pick.host = it.value
		names, err := browserNames()
		if err != nil {
			m.pick = nil
			m.status = stui.StatusErr.Render(err.Error())
			return m, nil
		}
		m.pick.step = pickBrowser
		m.pick.list = newPickList(pickItems(names), m.mdListW, m.mdHeight)
		return m, nil
	case pickBrowser:
		m.pick.browser = it.value
		profiles, err := browserProfiles(it.value)
		if err != nil {
			m.pick = nil
			m.status = stui.StatusErr.Render(err.Error())
			return m, nil
		}
		m.pick.step = pickProfile
		m.pick.list = newPickList(profileItems(profiles), m.mdListW, m.mdHeight)
		return m, nil
	case pickProfile:
		ep := state.Endpoint{Host: m.pick.host, Browser: m.pick.browser, Profile: it.value}
		self := m.self
		m.pick = nil
		return m, addBrowserCmd(self, ep)
	}
	return m, nil
}

func (m *browsersModel) View() string {
	if m.loading {
		return m.spin.View() + " Loading tracked browsers…"
	}
	if m.pick != nil {
		return m.pickView()
	}

	if len(m.allItems) == 0 {
		return stui.Dim.Render("No tracked browsers. Press + to add one.")
	}

	split := stui.MasterDetail(m.list.View(), renderBrowserDetail(m.list.SelectedItem()), m.mdListW, m.mdDetailW, m.mdHeight, m.mdShowDetail)
	body := lipgloss.JoinVertical(lipgloss.Left, m.filter.View(len(m.list.Items()), len(m.allItems)), split)
	if m.confirm != nil {
		body = lipgloss.JoinVertical(lipgloss.Left, body, stui.ConfirmBox.Render(m.confirm.prompt))
	}
	if m.status != "" {
		body = lipgloss.JoinVertical(lipgloss.Left, body, m.status)
	}
	return body
}

// pickView renders the active staged-picker step, or a guidance line when the
// scan turned up no choices to make.
func (m *browsersModel) pickView() string {
	var head, hint string
	switch m.pick.step {
	case pickHost:
		head = "Add browser · pick a host"
		hint = "enter to pick · esc to cancel"
	case pickBrowser:
		head = "Add browser · pick a browser on " + m.pick.host
		hint = "enter to pick · esc to cancel"
	case pickProfile:
		head = "Add browser · pick a " + m.pick.browser + " profile"
		hint = "enter to pick · esc to cancel"
	}
	if len(m.pick.list.Items()) == 0 {
		empty := stui.Dim.Render("No " + m.pick.browser + " profiles with a cookie store found on this host.")
		return lipgloss.JoinVertical(lipgloss.Left, stui.DetailTitle.Render(head), empty, stui.Dim.Render("esc to cancel"))
	}
	box := stui.MasterDetail(m.pick.list.View(), "", m.mdListW, 0, m.mdHeight, false)
	return lipgloss.JoinVertical(lipgloss.Left, stui.DetailTitle.Render(head), box, stui.Dim.Render(hint))
}

// newPickList builds a borderless single-column list for one staged-picker step.
func newPickList(items []list.Item, width, height int) list.Model {
	l := list.New(items, pickDelegate{}, width, height)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.DisableQuitKeybindings()
	return l
}

// selectedID reports the id of the cursor row, or "" when the list is empty, so
// a re-render can restore the selection.
func selectedID(l list.Model) string {
	if it, ok := l.SelectedItem().(browserItem); ok {
		return string(it.endpoint.ID())
	}
	return ""
}

// selectID moves the cursor back onto the row with the given endpoint id.
func selectID(l *list.Model, id string) {
	if id == "" {
		return
	}
	for i, raw := range l.Items() {
		if it, ok := raw.(browserItem); ok && string(it.endpoint.ID()) == id {
			l.Select(i)
			return
		}
	}
}

// browserNames returns the registered browser names, sorted, for the add
// picker's browser step.
func browserNames() ([]string, error) {
	registry, err := cookie.Registry()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, string(n))
	}
	sort.Strings(names)
	return names, nil
}

// browserProfiles scans the named browser's local data root for profiles that
// hold a cookie store, enriched with display name and email, the choices the add
// picker's profile step offers.
func browserProfiles(name string) ([]cookie.Profile, error) {
	browser, err := cookie.Lookup(cookie.BrowserName(name))
	if err != nil {
		return nil, err
	}
	return browser.Profiles()
}

// loadBrowsersCmd resolves the mesh and the tracked endpoints, stamping each with
// whether its profile directory is present on this host. Discovery is fast and
// cancellation tears down the whole program, so it builds its own ctx.
func loadBrowsersCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		self, peers, err := mesh.Resolve(ctx)
		if err != nil {
			return browsersLoadedMsg{err: err}
		}
		st, err := state.New(paths.Config).Load(ctx)
		if err != nil {
			return browsersLoadedMsg{err: fmt.Errorf("load state: %w", err)}
		}
		endpoints := st.Endpoints()
		sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID() < endpoints[j].ID() })
		statuses := make([]endpointStatus, len(endpoints))
		for i, ep := range endpoints {
			statuses[i] = endpointStatus{endpoint: ep, present: profilePresent(ep)}
		}
		return browsersLoadedMsg{self: self, peers: peers, endpoints: statuses}
	}
}

// profilePresent reports whether an endpoint's profile directory exists on this
// host, the same presence the watch supervisor keys its items on. A lookup error
// (an endpoint naming an unknown browser) reads as absent.
func profilePresent(ep state.Endpoint) bool {
	browser, err := cookie.Lookup(cookie.BrowserName(ep.Browser))
	if err != nil {
		return false
	}
	info, err := os.Stat(browser.ProfileDir(ep.Profile))
	return err == nil && info.IsDir()
}

// addBrowserCmd admits an endpoint into the convergent registry and records
// self_target, the same write the non-interactive `browser add` performs.
func addBrowserCmd(self string, ep state.Endpoint) tea.Cmd {
	return func() tea.Msg {
		err := state.New(paths.Config).AddBrowser(context.Background(), self, ep)
		return browserMutatedMsg{verb: "tracking", endpoint: ep, err: err}
	}
}

// removeBrowserCmd tombstones an endpoint in the convergent registry, the same
// write the non-interactive `browser rm` performs.
func removeBrowserCmd(ep state.Endpoint) tea.Cmd {
	return func() tea.Msg {
		err := state.New(paths.Config).RemoveBrowser(context.Background(), ep)
		return browserMutatedMsg{verb: "untracked", endpoint: ep, err: err}
	}
}
