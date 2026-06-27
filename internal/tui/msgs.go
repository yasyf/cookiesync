package tui

import "github.com/yasyf/cookiesync/internal/state"

// browsersLoadedMsg carries the tracked endpoints and the resolved mesh (self
// plus peers) back from the initial async load, or the error that aborted it.
type browsersLoadedMsg struct {
	self      string
	peers     []string
	endpoints []endpointStatus
	err       error
}

// browserMutatedMsg reports the result of an add or remove write to the
// convergent registry, naming the endpoint so the status line can echo it.
type browserMutatedMsg struct {
	verb     string
	endpoint state.Endpoint
	err      error
}

// endpointStatus pairs a tracked endpoint with whether its profile directory is
// present on this host, the same presence the watch supervisor keys items on.
type endpointStatus struct {
	endpoint state.Endpoint
	present  bool
}
