package bridge

import "errors"

// WindowMode is how a bridge open asks for Chrome's window: left to the host,
// or stated explicitly by the caller.
type WindowMode int

const (
	// WindowAuto runs Chrome headed where the daemon has a display and
	// headless where it has none.
	WindowAuto WindowMode = iota
	// WindowHeaded requires a headed Chrome and refuses a host with no display.
	WindowHeaded
	// WindowHeadless runs Chrome with --headless=new.
	WindowHeadless
)

var errNoDisplay = errors.New("bridge: a headed chrome needs a display, and the daemon has neither DISPLAY nor WAYLAND_DISPLAY; open the bridge with --headless or run the daemon inside a graphical session")

// ResolveHeaded decides whether this host's bridge Chrome runs headed for mode.
func ResolveHeaded(mode WindowMode) (bool, error) {
	return resolveHeaded(mode, hasDisplay())
}

func resolveHeaded(mode WindowMode, display bool) (bool, error) {
	switch mode {
	case WindowHeadless:
		return false, nil
	case WindowHeaded:
		if !display {
			return false, errNoDisplay
		}
		return true, nil
	case WindowAuto:
		return display, nil
	}
	panic("bridge: unknown window mode")
}
