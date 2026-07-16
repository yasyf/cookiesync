# cookiesync Development Guide

Sync your browser cookies across your Macs. A macOS CLI (`cookiesync`) that
streams cookies out of the local browser store behind one Touch ID tap, caches the
Safe Storage key for a short window, and converges the union of every tracked
browser profile across your hosts over ssh.

## Repository Structure

```
cookiesync/
├── main.go              # Entrypoint; injects the release version into the CLI
├── internal/
│   ├── cli/             # Cobra wiring: root, browser, auth, cookies, sync, reconcile, rpc, watch, install/uninstall, doctor, route-consent, self
│   └── paths/           # Per-tool config dir + daemon RPC socket under ~/.config/cookiesync (forwards to synckit/hostregistry)
├── helper/              # Signed Swift Secure-Enclave key helper (Developer-ID .app); fetched via Homebrew at install
├── .github/workflows/   # ci.yml (vet/test/build, golangci-lint, govulncheck)
├── docs/assets/         # Mascot logo, README banner, social-preview card
├── AGENTS.md            # This file — shared conventions
└── README.md            # Project overview
```

The generic sync substrate (host registry, RPC over a unix socket, convergent
registry, launchd service plumbing) lives in the shared
`github.com/yasyf/synckit` module, consumed as a published version pinned in
go.mod (no local `replace`; to build against in-flight synckit changes, add a
temporary `go mod edit -replace github.com/yasyf/synckit=../synckit` and drop
it before committing). cookiesync drives it for its config dir, socket path,
and peer registry; the cookie-specific subsystems (crypto, sqlite stores,
merge, the Swift helper bridge, the watch daemon) live here.
