# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1] - 2026-07-10

### Fixed
- The Homebrew cask restarts the resident helper with `launchctl kickstart` after every install and
  upgrade. A cask upgrade swaps the binary on disk but never touches launchd, so the old helper kept
  serving a stale RPC dispatcher that rejected `get_web_storage` until a manual restart. First
  install is a no-op since the agent doesn't exist until `synckitd install`.

## [0.10.0] - 2026-07-08

### Added
- Web-storage capture. `cookiesync cookies` now reads each origin's localStorage and sessionStorage
  from the browser's LevelDB stores alongside cookies, so localStorage-auth sites (whose login token
  lives in localStorage, not a cookie) drive logged-in in `agent-browser` sessions. `--format
  playwright` emits the storageState `origins[]` with localStorage; a new `--format webstorage`
  sidecar carries both localStorage and sessionStorage (Playwright storageState has no sessionStorage
  slot). A new local-only `get_web_storage` RPC rides the same consent grant as cookies (no extra
  Touch ID tap) and discards the key, since web storage is unencrypted at rest. IndexedDB is not
  captured — its LevelDB uses a custom comparator and V8-serialized values.
- `cookiesync requestor` prints the stable requestor token — the identity that keys grant reuse —
  so external tools can scope per-session state to this caller. Falls back to a `pid-<ppid>` token
  outside a recognized agent session.

## [0.9.0] - 2026-07-03

### Changed
- Converge logs an unreachable peer once per outage instead of warning on every pass, and notes the
  outage duration on recovery.
- Bump synckit to v0.8.0 (from v0.7.1): ssh peer targets pin to tailscale MagicDNS FQDNs; after re-adding a host to the mesh, re-track that host's browser endpoints (cookiesync browser rm/add) so their registry keys carry the new host string.

## [0.8.3] - 2026-07-03

### Fixed
- `cookiesync doctor` treats a locked keybag as healthy instead of reporting a key-cache FAIL. A
  locked or away user session makes the live auth probe refuse, which rendered as a raw FAIL on a
  perfectly healthy machine; doctor now renders that row OK with a note and keeps
  degraded-while-available as the one genuine FAIL.

## [0.8.2] - 2026-07-03

### Added
- A stable consent requestor derived from agent-session env vars. `COOKIESYNC_REQUESTOR` wins when
  set, else `CLAUDE_CODE_SESSION_ID`; the token rides every grant-gated call so one agent session
  reuses its grant instead of re-tapping Touch ID on every invocation.

## [0.8.1] - 2026-07-03

### Added
- Browser-less `cookiesync cookies` unions every registered endpoint. Local browsers serve from a
  warm grant or ride a single consent sheet, remote endpoints stream over ssh, and cold or
  unreachable ones are skipped with a warning. Browser-less `cookiesync auth` primes all local
  browsers in one batch flight, and the new `cookie.MergeRanked` settles union conflicts
  newest-first, preferring the local machine on a tie.

### Changed
- Bump synckit to v0.7.1, pulling the fix for the transport crash on a stale exchange after a
  converge peer timeout.
- The cookie payload now streams to stdout while warnings ride stderr; `--profile` without
  `--browser` fails fast, and the implicit chrome default is dropped.

### Fixed
- Three consent holes in the union fan-out are closed. A browser-less read against a cold peer no
  longer bounces a Touch ID sheet back to the calling Mac and routes per that peer's own config
  instead of failing closed, every release path now derives routing through the one shared rule so
  `ConsentRouteHard` is honored everywhere and a mid-call presence flip can never fire a second
  sheet or mix consent surfaces, and the ssh leg fences untrusted URLs behind `--` so a URL
  spelled like a flag can't defeat the recursion guard.

## [0.8.0] - 2026-07-03

### Added
- One Touch ID tap now covers every tracked browser. Each browser's Safe Storage key
  batch-releases under a single LAContext, and grants are keyed per requesting principal with a
  mode-dependent TTL of 1h under the Secure Enclave and 5m degraded. Requires synckit v0.7.0.

### Fixed
- The blank auth sheet caused by the bare-ACL vault probe.

## [0.7.0] - 2026-07-02

### Fixed
- Screen-shared and locked hosts no longer deadlock convergence, via synckit v0.6.0's concurrent
  RPC dispatch plus per-endpoint apply locks, a singleflight around `primeAuth`, a prompt gate so
  cold primes never stack two Touch ID sheets, and real deadlines on remote calls. A daemon whose
  keybag is unavailable at start now falls back to a RAM-only key cache instead of crash-looping.
  The degradation is loud, with a WARN at startup, a degraded flag on `auth_status`, and a doctor
  line, and the cache swaps back to the Secure Enclave once the keybag returns.

## [0.6.4] - 2026-07-01

### Changed
- Release pipeline only. The CLI and keyhelper now ship through the shared signed/notarized cask
  release workflows.

## [0.6.3] - 2026-07-01

### Added
- Consent routes to the present human when a host is Screen Shared. An inbound Screen Sharing
  session now folds into `SessionSnapshot.ScreenShared`, so a shared but unattended host stops
  prompting Touch ID locally and routes the gate to a live peer. `route-consent <target> --hard`
  forces a deterministic redirect independent of presence.

## [0.6.2] - 2026-06-27

### Added
- `cookiesync browser profiles <browser> [--json]` — list a browser's on-disk profiles (dir, display
  name, account email) on the host it runs on.

### Fixed
- The TUI's browser-add flow now lists the *selected host's* profiles. When the host is a peer it
  enumerates that host's profiles over ssh (`cookiesync browser profiles --json`, bounded timeout)
  instead of showing the local machine's. The tracked endpoint still stores the on-disk profile
  directory.
- The Hosts tab seeds the registered mesh instantly and revalidates in place (via synckit v0.4.2).

## [0.6.1] - 2026-06-27

### Fixed
- The TUI's browser-add profile picker now shows each profile's display name and account email
  (read from the browser's `Local State`) instead of bare directory names, and drops Arc's internal
  system profile. The tracked endpoint still stores the on-disk profile directory.
- The Hosts tab sorts registered mesh peers above discovered candidates (via synckit v0.4.1).

## [0.6.0] - 2026-06-27

### Added
- A terminal UI: bare `cookiesync` on a TTY (or `cookiesync tui`) opens a Browsers tab listing the
  tracked endpoints with per-profile presence and a full-picker add flow (host → browser → profile),
  plus the shared Hosts tab from synckit for discovering and bootstrapping peers. `browser add/ls/rm`
  stays the non-interactive path.
- `cookie.Browser.Profiles()` — enumerates a browser's on-disk profiles (subdirs of its data root
  that hold a Cookies store), feeding the add-flow's profile picker.

### Changed
- Adopt synckit v0.4.0's shared `tui` package. The UI shell and Hosts tab are shared with reposync,
  and the host-discovery fixes ride along: the local Mac no longer lists itself in Hosts, and a peer
  with the daemon installed reads "installed" instead of "reachable, not installed".

## [0.5.0] - 2026-06-26

### Changed
- Adopt synckit v0.3.0's typed RPC contract. The resident helper now serves synckitd's typed
  `syncservice` methods (`svc.capabilities`/`list`/`reconcile`/`sync`/`get_state`) on its RPC
  socket — the warm Secure-Enclave key stays resident — and a new `cookiesync rpc-serve` bridges
  a peer's stdin/stdout frames to that socket so a cross-host sync reuses the warm key. Cross-host
  registry fetch goes through typed `svc.get_state` over ssh-stdio. The manifest's `actions` +
  `watch.list_cmd` are replaced by a `service{transport:"socket",serve_args,sock}` block.

### Removed
- The `sync`, `reconcile`, `state` (get-json/apply-json), and `list` CLI commands — now served
  over RPC. The cookie value-union fleet protocol (`rpc extract`/`rpc apply`) is unchanged.

## [0.4.0] - 2026-06-25

### Changed
- Adopt the `synckitd` daemon from github.com/yasyf/synckit v0.2.0. cookiesync is now a
  declarative consumer driven by synckitd through a manifest + CLI action contract. The
  resident `cookiesync helper-serve` keeps only the Secure-Enclave key cache and Touch ID
  consent gate.

### Added
- `cookiesync list --json` and `cookiesync state apply-json`; `sync --origin`.

### Removed
- The built-in watch loop, the reposync host-mesh shell-out, and per-tool launchd;
  `synckitd install` now owns the agents. The host mesh is read from the shared
  `~/.config/synckit`.

[Unreleased]: https://github.com/yasyf/cookiesync/compare/v0.10.1...HEAD
[0.10.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.1
[0.10.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.0
[0.9.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.9.0
[0.8.3]: https://github.com/yasyf/cookiesync/releases/tag/v0.8.3
[0.8.2]: https://github.com/yasyf/cookiesync/releases/tag/v0.8.2
[0.8.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.8.1
[0.8.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.8.0
[0.7.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.7.0
[0.6.4]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.4
[0.6.3]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.3
[0.6.2]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.2
[0.6.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.1
[0.6.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.0
[0.5.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.5.0
[0.4.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.4.0
