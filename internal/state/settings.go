package state

import (
	"fmt"
	"strconv"
	"time"
)

// Settings are the cadence knobs the sync, watch, and reconcile loops read,
// serialized as compact Go-style duration strings ("15m", "3s") to match the Python
// on-disk form. The zero Settings is not the default; build the defaults with
// DefaultSettings.
type Settings struct {
	Interval      time.Duration
	IdleThreshold time.Duration
	WatchDebounce time.Duration
	AuthTTL       time.Duration
}

// DefaultSettings returns the cadence defaults: a 15m reconcile interval, a 5m idle
// threshold, a 3s watch debounce, and a 5m key-cache TTL — the same defaults as the
// Python Settings dataclass.
func DefaultSettings() Settings {
	return Settings{
		Interval:      15 * time.Minute,
		IdleThreshold: 5 * time.Minute,
		WatchDebounce: 3 * time.Second,
		AuthTTL:       5 * time.Minute,
	}
}

// durationUnits orders the Go-style duration suffixes from largest to smallest, the
// search order FormatDuration uses to pick the most compact rendering.
var durationUnits = []struct {
	unit string
	size time.Duration
}{
	{"h", time.Hour},
	{"m", time.Minute},
	{"s", time.Second},
}

// ParseDuration parses a Go-style duration string such as "15m" or "90s" into a
// time.Duration, supporting the h/m/s units the on-disk settings use. It mirrors the
// Python parse_duration: an integer count followed by a single unit suffix.
func ParseDuration(text string) (time.Duration, error) {
	if len(text) < 2 {
		return 0, fmt.Errorf("invalid duration %q", text)
	}
	suffix := text[len(text)-1:]
	for _, u := range durationUnits {
		if suffix == u.unit {
			count, err := strconv.Atoi(text[:len(text)-1])
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q: %w", text, err)
			}
			return time.Duration(count) * u.size, nil
		}
	}
	return 0, fmt.Errorf("invalid duration unit in %q (want h, m, or s)", text)
}

// FormatDuration renders d as the most compact Go-style string, e.g. "15m" or "90s",
// choosing the largest unit that divides d evenly. It mirrors the Python
// format_duration. A sub-second or otherwise-indivisible duration falls back to whole
// seconds.
func FormatDuration(d time.Duration) string {
	secs := int64((d + time.Second/2) / time.Second)
	for _, u := range durationUnits {
		size := int64(u.size / time.Second)
		if secs%size == 0 {
			return strconv.FormatInt(secs/size, 10) + u.unit
		}
	}
	return strconv.FormatInt(secs, 10) + "s"
}

// settingsJSON is the on-disk shape of Settings: each knob as a duration string.
type settingsJSON struct {
	Interval      string `json:"interval"`
	IdleThreshold string `json:"idle_threshold"`
	WatchDebounce string `json:"watch_debounce"`
	AuthTTL       string `json:"auth_ttl"`
}

func (s Settings) toJSON() settingsJSON {
	return settingsJSON{
		Interval:      FormatDuration(s.Interval),
		IdleThreshold: FormatDuration(s.IdleThreshold),
		WatchDebounce: FormatDuration(s.WatchDebounce),
		AuthTTL:       FormatDuration(s.AuthTTL),
	}
}

func settingsFromJSON(raw settingsJSON) (Settings, error) {
	var (
		s   Settings
		err error
	)
	if s.Interval, err = ParseDuration(raw.Interval); err != nil {
		return Settings{}, fmt.Errorf("interval: %w", err)
	}
	if s.IdleThreshold, err = ParseDuration(raw.IdleThreshold); err != nil {
		return Settings{}, fmt.Errorf("idle_threshold: %w", err)
	}
	if s.WatchDebounce, err = ParseDuration(raw.WatchDebounce); err != nil {
		return Settings{}, fmt.Errorf("watch_debounce: %w", err)
	}
	if s.AuthTTL, err = ParseDuration(raw.AuthTTL); err != nil {
		return Settings{}, fmt.Errorf("auth_ttl: %w", err)
	}
	return s, nil
}
