package tui

import "github.com/charmbracelet/bubbles/key"

// browsersKeyMap holds the Browsers screen's contextual bindings.
type browsersKeyMap struct {
	Filter  key.Binding
	Add     key.Binding
	Remove  key.Binding
	Confirm key.Binding
	Cancel  key.Binding
	Pick    key.Binding
}

func newBrowsersKeyMap() browsersKeyMap {
	return browsersKeyMap{
		Filter:  key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Add:     key.NewBinding(key.WithKeys("+"), key.WithHelp("+", "add browser")),
		Remove:  key.NewBinding(key.WithKeys("r", "delete", "backspace"), key.WithHelp("r", "remove")),
		Confirm: key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "confirm")),
		Cancel:  key.NewBinding(key.WithKeys("n", "esc", "ctrl+c"), key.WithHelp("esc", "cancel")),
		Pick:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
	}
}
