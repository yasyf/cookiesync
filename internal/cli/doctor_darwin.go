package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/transfer"
	"github.com/yasyf/synckit/authkit"
	"github.com/yasyf/synckit/manifest"
)

const (
	doctorShort = "Check the signed key helper, the resident helper, the synckit mesh and manifest, and the state."
	socketHint  = "run 'synckitd install' to start the resident helper (cookiesync helper-serve)"
)

// vaultName is the Secure-Enclave vault item the contract probe checks for; the helper
// reports its biometry/passcode/vault status on one line.
const vaultName = "cookiesync"

// realDoctorEnv wires the production health checks.
func realDoctorEnv() doctorEnv {
	return doctorEnv{
		helper:   checkHelper,
		socket:   checkSocket,
		keyCache: checkKeyCache,
		mesh:     checkMesh,
		host: func(ctx context.Context) []check {
			var checks []check
			if tcc, ok := checkTCC(ctx, mesh.Resolve); ok {
				checks = append(checks, tcc)
			}
			return append(checks, checkManifest(ctx))
		},
		state:      checkState,
		tracked:    checkTracked,
		quarantine: checkQuarantine,
	}
}

// checkHelper confirms the signed key helper is installed and supports the key-helper
// contract. It resolves the helper (failing closed when absent, like the Python
// HelperState.MISSING), then runs the read-only vault-status probe: exit 0 or 2 with a
// "biometry=… passcode=… vault=…" line means the contract is supported; a stale helper
// (no such line) fails. Mirrors the Python doctor's signature + contract check.
func checkHelper(ctx context.Context) check {
	binary, err := authkit.RequireHelper()
	if err != nil {
		return check{label: "key helper", detail: err.Error()}
	}
	res, err := helper.Bridge{}.VaultStatus(ctx, vaultName)
	if err != nil {
		return check{label: "key helper", detail: fmt.Sprintf("present at %s but the contract probe failed: %v", binary, err)}
	}
	if !strings.Contains(string(res.Stdout), "vault=") {
		return check{label: "key helper", detail: fmt.Sprintf("present at %s but does not support the key-helper contract (stale cask); reinstall via 'cookiesync install'", binary)}
	}
	return check{label: "key helper", ok: true, detail: fmt.Sprintf("%s (Developer ID signed, key-helper contract supported)", binary)}
}

// keyCacheCheck renders the key-cache health line from the daemon's degradation and
// keybag-availability flags. The cache may demote and re-heal during the daemon's life. A
// locked keybag makes either state expected; only an in-memory cache while the keybag is
// available is a genuine FAIL.
func keyCacheCheck(status keyCacheStatus) check {
	switch {
	case status.Degraded && status.Locked:
		return check{label: "key cache", ok: true, detail: "in process memory (keybag locked; re-heals Secure-Enclave wrapped on the next authorization)"}
	case status.Degraded:
		return check{label: "key cache", detail: "degraded after a Secure Enclave presence refusal; run 'cookiesync auth' to re-prime"}
	case status.Locked:
		return check{label: "key cache", ok: true, detail: "Secure-Enclave wrapped (keybag locked: screen locked or session away)"}
	default:
		return check{label: "key cache", ok: true, detail: "Secure-Enclave wrapped"}
	}
}

// checkTCC emits an informational peer-access pointer when cross-host pulls apply. It
// never fails because a TCC denial cannot be confirmed without Full Disk Access.
func checkTCC(ctx context.Context, resolve func(context.Context) (string, []string, error)) (check, bool) {
	_, peers, err := resolve(ctx)
	if err != nil || len(peers) == 0 {
		return check{}, false
	}
	return check{
		label:  "peer TCC",
		ok:     true,
		detail: "cross-host pulls use ssh; if this host times out pulling from a peer, check Full Disk Access for the peer's ssh identity (sshd or tailscaled)",
	}, true
}

// checkManifest confirms cookiesync's synckit manifest is registered AND validates
// against the current schema — the typed service block synckitd drives, not the old
// action templates — so a stale manifest from a prior install is caught. A missing
// manifest means 'cookiesync install' never ran; a manifest that no longer validates
// means 're-run cookiesync install'. manifest.Load both decodes and validates.
func checkManifest(_ context.Context) check {
	path, err := manifestPath()
	if err != nil {
		return check{label: "manifest", detail: err.Error()}
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		return check{label: "manifest", detail: fmt.Sprintf("not registered at %s; run 'cookiesync install'", path)}
	}
	m, err := manifest.Load(path)
	if err != nil {
		return check{label: "manifest", detail: fmt.Sprintf("registered at %s but does not validate (stale schema); re-run 'cookiesync install': %v", path, err)}
	}
	if m.Service.Kind != "resident" || m.Service.SchemaFingerprint != transfer.Fingerprint {
		return check{label: "manifest", detail: fmt.Sprintf("service contract = %+v at %s, want exact resident transfer contract; re-run 'cookiesync install'", m.Service, path)}
	}
	return check{label: "manifest", ok: true, detail: path}
}

// noteHelper prints a one-line note on the signed key helper before install proceeds,
// mirroring the Python ensure_helper's status line. It never fetches or blocks: a
// missing helper is reported, and the manifest registers anyway (the helper fails closed
// at runtime without it).
func noteHelper(cmd *cobra.Command) {
	if binary, err := authkit.RequireHelper(); err == nil {
		cmd.Printf("Key helper present: %s\n", binary)
		return
	}
	cmd.PrintErrln("Key helper not installed; install it via Homebrew: brew install --cask authkit")
}
