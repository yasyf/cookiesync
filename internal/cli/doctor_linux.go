package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/rpc"
)

const (
	doctorShort = "Check the supervisor, the resident helper, the key cache, the host mesh, the browsers, and the state."
	socketHint  = "run 'cookiesync install' under a running 'cookiesync supervise' to start the resident helper (cookiesync helper-serve)"
)

func realDoctorEnv() doctorEnv {
	return doctorEnv{
		helper:   checkSupervisor,
		socket:   checkSocket,
		keyCache: checkKeyCache,
		mesh:     checkMesh,
		host: func(context.Context) []check {
			return []check{checkBrowserRoots(), checkBridgeChrome()}
		},
		state:      checkState,
		tracked:    checkTracked,
		quarantine: checkQuarantine,
	}
}

func checkSupervisor(ctx context.Context) check {
	ensured, err := rpc.Ensure(ctx)
	if err != nil {
		return check{label: "supervisor", detail: err.Error()}
	}
	return check{label: "supervisor", ok: true, detail: fmt.Sprintf("resident helper ensured (%s)", ensured.Did)}
}

func keyCacheCheck(status keyCacheStatus) check {
	if !status.Degraded {
		return check{label: "key cache", detail: "the helper reports a sealed cache tier this host cannot provide; restart it with 'cookiesync install'"}
	}
	return check{label: "key cache", ok: true, detail: fmt.Sprintf("in process memory only; cached keys and grants expire within %d minutes", int(cache.DegradedTTL.Minutes()))}
}

func checkBrowserRoots() check {
	registry, err := cookie.Registry()
	if err != nil {
		return check{label: "browser roots", detail: err.Error()}
	}
	names := make([]cookie.BrowserName, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	installed := 0
	details := make([]string, 0, len(names))
	for _, name := range names {
		b := registry[name]
		if _, err := os.Stat(b.DataRoot); errors.Is(err, fs.ErrNotExist) {
			details = append(details, fmt.Sprintf("%s absent at %s", name, b.DataRoot))
			continue
		}
		profiles, err := b.Profiles()
		if err != nil {
			return check{label: "browser roots", detail: fmt.Sprintf("%s at %s: %v", name, b.DataRoot, err)}
		}
		installed++
		details = append(details, fmt.Sprintf("%s at %s (%d profiles)", name, b.DataRoot, len(profiles)))
	}
	return check{label: "browser roots", ok: installed > 0, detail: strings.Join(details, "; ")}
}

func checkBridgeChrome() check {
	binary, err := bridge.ResolveHostBinary()
	if err != nil {
		return check{label: "bridge chrome", detail: err.Error()}
	}
	return check{label: "bridge chrome", ok: true, detail: binary}
}
