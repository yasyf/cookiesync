package cli

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/syncservice"
)

// check is one doctor health check's outcome: a label, whether it passed, and a detail
// line shown after the status.
type check struct {
	label  string
	ok     bool
	detail string
}

// doctorEnv is the set of probes the doctor runs. The helper slot is the platform's key
// backend (the signed helper on macOS, the supervisor on Linux) and host holds the
// platform's own checks; every other probe returns one check. Tests inject this seam so doctor runs without a signed helper,
// a live helper, or a registered mesh. The zero value is not usable; build it with
// realDoctorEnv.
type doctorEnv struct {
	helper     func(ctx context.Context) check
	socket     func(ctx context.Context) check
	keyCache   func(ctx context.Context) check
	mesh       func(ctx context.Context) check
	host       func(ctx context.Context) []check
	state      func(ctx context.Context) check
	tracked    func(ctx context.Context) check
	quarantine func(ctx context.Context) []check
}

// checks runs every probe in a fixed order so the report is deterministic.
func (e doctorEnv) checks(ctx context.Context) []check {
	checks := []check{
		e.helper(ctx),
		e.socket(ctx),
		e.keyCache(ctx),
		e.mesh(ctx),
	}
	checks = append(checks, e.host(ctx)...)
	checks = append(checks,
		e.state(ctx),
		e.tracked(ctx),
	)
	return append(checks, e.quarantine(ctx)...)
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: doctorShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, realDoctorEnv())
		},
	}
	return cmd
}

// runDoctor runs every health check, prints one OK/FAIL line each with its detail, and
// returns a non-empty error (exit 1) when any check failed — matching the Python
// doctor's exit-0-on-success, raise-on-failure behavior, broadened to the full set.
func runDoctor(cmd *cobra.Command, env doctorEnv) error {
	checks := env.checks(cmd.Context())
	failed := 0
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			status = "FAIL"
			failed++
		}
		cmd.Printf("%-4s %s: %s\n", status, c.label, c.detail)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	return nil
}

// checkSocket confirms the resident helper is reachable AND speaks the typed sync
// contract synckitd drives — the "is the helper up and serving svc.*?" check. It opens
// the helper by name and round-trips svc.capabilities, the lightest typed call (no
// cookie store read, no SE key), so a green line proves the contract is live end to end
// through the same resident helper Synckit targets for export, apply, and
// reconciliation.
func checkSocket(ctx context.Context) check {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := syncservice.NewClient(syncservice.Resident(paths.ToolName))
	defer func() { _ = client.Close() }()
	if _, err := client.Capabilities(probeCtx); err != nil {
		return check{label: "helper socket", detail: fmt.Sprintf("not serving the typed contract; %s: %v", socketHint, err)}
	}
	return check{label: "helper socket", ok: true, detail: "resident helper (typed svc contract)"}
}

// keyCacheStatus is the slice of the auth_status reply the key-cache check reads: the
// cache-global degradation flag and whether the daemon user's keybag is unavailable
// (screen locked, session absent, or held by another user). A locked keybag makes an
// in-memory degradation and an Enclave unavailability expected, healthy states.
type keyCacheStatus struct {
	Degraded bool `json:"degraded"`
	Locked   bool `json:"keybag_locked"`
}

// checkKeyCache confirms the resident daemon's current key-cache wrapping state. The
// flags are cache-global, so the probe reads them off auth_status for the default chrome
// endpoint — the endpoint itself is immaterial — and keyCacheCheck renders them.
func checkKeyCache(ctx context.Context) check {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var status keyCacheStatus
	if err := rpc.CallJSON(probeCtx, "auth_status", map[string]any{"browser": "chrome"}, &status); err != nil {
		return check{label: "key cache", detail: fmt.Sprintf("auth_status probe failed: %v", err)}
	}
	return keyCacheCheck(status)
}

// checkMesh confirms this host has joined the synckit host mesh — that the shared
// registry reports a self target. cookiesync keys every endpoint and converges across
// the mesh, so an unjoined host syncs nothing.
func checkMesh(ctx context.Context) check {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return check{label: "mesh", detail: err.Error()}
	}
	return check{label: "mesh", ok: true, detail: fmt.Sprintf("self %s", self)}
}

// checkState confirms cookiesync's state.json parses, so a malformed file is caught
// before a sync trips on it.
func checkState(ctx context.Context) check {
	if _, err := state.New(paths.Config).Load(ctx); err != nil {
		return check{label: "state", detail: err.Error()}
	}
	return check{label: "state", ok: true, detail: "readable"}
}

// checkTracked confirms at least one browser endpoint is registered, since a sync with
// no tracked endpoints does nothing.
func checkTracked(ctx context.Context) check {
	st, err := state.New(paths.Config).Load(ctx)
	if err != nil {
		return check{label: "browsers", detail: err.Error()}
	}
	n := len(st.Endpoints())
	if n == 0 {
		return check{label: "browsers", detail: "no browser endpoints tracked; run 'cookiesync browser add'"}
	}
	return check{label: "browsers", ok: true, detail: fmt.Sprintf("%d tracked", n)}
}

// checkQuarantine emits one failing line per endpoint the mass-drop quarantine holds
// out of the merge, read from the persisted rowcount baselines. A healthy host emits
// nothing.
func checkQuarantine(ctx context.Context) []check {
	st, err := state.New(paths.Config).Load(ctx)
	if err != nil {
		return []check{{label: "quarantine", detail: err.Error()}}
	}
	return quarantineChecks(st.Baselines)
}

// quarantineChecks renders one FAIL line per quarantined endpoint, sorted by id.
func quarantineChecks(baselines map[string]state.Baseline) []check {
	ids := make([]string, 0, len(baselines))
	for id, baseline := range baselines {
		if baseline.Quarantined {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	checks := make([]check, 0, len(ids))
	for _, id := range ids {
		baseline := baselines[id]
		recoverRows := int(float64(baseline.Rows) * engine.QuarantineRecoverFraction)
		checks = append(checks, check{
			label: "quarantine",
			detail: fmt.Sprintf("%s: rowcount collapsed to %d vs baseline %d; excluded from merge inputs until it recovers to >= %d rows",
				id, baseline.QuarantinedRows, baseline.Rows, recoverRows),
		})
	}
	return checks
}
