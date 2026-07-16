# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0]

### Changed
- The `cookiesync` CLI now ships inside a signed, notarized, stapled `CookieSync.app`,
  and the Homebrew cask symlinks the command to the bundle-inner binary. macOS keys a
  bare binary's Automation and app-bundle (kTCCServiceSystemPolicyAppBundles) approvals
  to its versioned Cellar path, so every `brew upgrade` used to land at a new path and
  re-prompt for access; a bundle is keyed by its identifier
  (`com.github.yasyf.cookiesync`) instead, so the grant survives upgrades. Because tccd
  attributes a nested binary to its enclosing bundle, both the interactive CLI and the
  synckit-driven resident helper LaunchAgent
  (`com.github.yasyf.synckit.helper.cookiesync`) now inherit that durable identity.

  **Upgrade note:** the first upgrade onto this build prompts once per service, because
  each one's identity moves from a path to the bundle — that is the last approval
  you'll be asked for, and it sheds any denials macOS had recorded against the old
  path.

## [0.15.0] - 2026-07-16

### Changed
- The Touch ID key helper is now the shared `authkit` cask; the `cookiesync-keyhelper`
  cask is retired and no longer built. A fresh `brew install cookiesync` pulls `authkit`
  as a cask dependency. An existing install swaps helpers by hand:

  ```sh
  brew uninstall --cask cookiesync-keyhelper
  brew install --cask authkit
  ```

  Existing vault items stay readable with no re-enrollment — authkit carries the same
  keychain access group.

## [0.14.2] - 2026-07-16

### Fixed
- Opening a bridge no longer fails on a `chrome-extension://` (or `chrome://`, `devtools://`)
  origin's web storage. Those privileged documents deny a `Page.navigate` + `localStorage`
  write, which aborted the whole seed with a SecurityError; such origins are now skipped, since
  their storage can't be replayed and is never part of a login.

## [0.14.1] - 2026-07-15

### Fixed
- Cookie writes are monotone on `last_update_utc`: an apply no longer overwrites a newer
  row with an older one. This closes the reproducible login clobber — a converge racing a
  fresh login used to re-plant the stale cookie after every browser restart, and the
  regression self-perpetuated because the browser never re-flushed its in-memory copy.
  `Write` now reports rows actually changed, so a stale apply returns `applied: 0`.
- Session-scoped and expired cookies no longer sync. Converge and the inbound apply
  handler drop them before merging: a logout on one host can't kill the login everywhere,
  and synced dead rows no longer vanish at the next browser startup.

### Added
- Converge warns when a source yields cookies stamped more than two minutes in the
  future; cross-host clock skew silently corrupts newest-wins merges.

## [0.14.0] - 2026-07-15

### Added
- `cookiesync bridge open [browser[:profile]]` launches a throwaway Chrome seeded with your
  real cookies and web storage behind one Touch ID tap, and exposes a live, token-gated CDP
  endpoint on loopback for agent-browser or any CDP client to drive. The bridge speaks CDP to
  Chrome over `--remote-debugging-pipe` — never an unauthenticated debugging port — and relays
  a single client's traffic byte-for-byte over a token-gated WebSocket; the browser is torn
  down when that client disconnects or the short bridge grant lapses. Cookies are seeded into
  an off-the-record context, so the decrypted state never lands on same-UID-readable disk.
  `bridge ls` and `bridge stop` manage running sessions.
- agent-browser can drive the bridge two ways: `ab --bridge <site>` opens one and connects the
  session to it, and a native `--provider cookiesync` plugin slots the bridge in wherever
  `--provider browserbase` sits.
- `cookiesync bridge open --host <peer>` opens the bridge on another Mac in the mesh and
  forwards it back over ssh. The peer runs its own consent tap (strict biometric, or routed to
  a third host per the peer's own config) and seeds the bridge with its own cookies locally —
  the Safe Storage key is read and used entirely on the peer and never crosses the wire. The
  origin spawns a detached `ssh -N -L` loopback forward, proves it up against the peer's
  token-gated `/json/version` before publishing the ws endpoint, and supervises it with a
  keepalive so the peer reaps the bridge the moment the origin goes away; the peer's ≤10-minute
  lease is the crash-durable ceiling if a hard power-off outruns the keepalive. `bridge ls` and
  `bridge stop` manage a cross-host bridge by the same host:browser:profile target as a local
  one.

## [0.11.1] - 2026-07-13

### Fixed
- A heal that swaps the degraded in-memory key wrapper over to the Secure Enclave no longer
  wipes a cached key that a concurrent request stored under the new wrapper. The swap used to
  clear the whole cache, which could drop an entry another in-flight prime had just written
  correctly Enclave-wrapped — a silent miss that forced one redundant Touch ID re-prime for an
  unrelated endpoint. The swap now evicts only the stale identity-wrapped entries left behind.
- A failed `cache-dropkey` at shutdown surfaces instead of reading as a clean close. Dropping
  the Enclave key checked only whether the helper could be spawned, not its exit code, so a
  nonzero drop — the key was not deleted — still reported success and cleared the wrapper. A
  nonzero exit is now returned as an error, leaving the key retryable rather than silently leaked.

## [0.10.4] - 2026-07-13

### Fixed
- `auth_status` no longer blocks past its 1.5s bound while a key-cache heal is mid-flight.
  The heal's `cache-newkey` helper subprocess — a human-timescale Touch ID presence prompt —
  ran while holding the cache lock every reader takes, so an in-flight heal stalled every
  status read past its deadline (a context timeout cannot interrupt a `sync.Mutex.Lock`).
  Readers now load the cached wrapper through an atomic pointer, lock-free, so status reads
  never queue behind an in-flight heal; heals stay serialized, one prompt at a time.
- `auth_status` derives its keybag verdict from an `ioreg`-only probe. The screen-share
  `netstat` probe bears on consent routing, not keybag availability, so it no longer runs on
  the doctor hot path (`ioreg` ~17ms, `netstat` ~4ms on a locked Mac). A cache read that
  outruns the bound after an unlocked probe now reports `degraded`, not a forced lock.

## [0.10.3] - 2026-07-12

### Fixed
- The browser-less union no longer hangs on a wedged peer. A peer's `get_cookies` leg is
  bounded at 15s (`unionReadTimeout`) instead of inheriting the 10-minute consent window,
  and a timed-out peer is skipped with a stderr warning naming the host and the likely
  cause (consent pending there, or the host is slow). Consent flows keep their full
  window; a pending Touch ID sheet on the peer survives the killed ssh, and the next
  union pull rides the resulting grant.
- The ssh runner's deadline now terminates the whole process subtree. `Setpgid` plus a
  process-group SIGKILL and a 5s `WaitDelay` replace the default cancel, which killed
  only the direct child and then blocked in `Wait` forever when a grandchild held the
  stdout pipe — the mechanism that could strand a remote call past `applyTimeout`.
- `auth_status` answers within 1.5s on a locked Mac. The doctor's 2s deadline never
  crossed the RPC socket, so a slow session probe (`ioreg`/`netstat` under screen share)
  ran under the dispatcher's 10-minute window and surfaced as a `key cache: i/o timeout`
  FAIL; the probe and cache read are now bounded, and a keybag that cannot be confirmed
  servable in time reports locked — rendered as the OK-with-note line, never an error.

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

[0.16.0]: https://github.com/yasyf/cookiesync/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.15.0
[0.14.2]: https://github.com/yasyf/cookiesync/releases/tag/v0.14.2
[0.14.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.14.1
[0.14.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.14.0
[0.11.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.11.1
[0.11.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.11.0
[0.10.5]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.5
[0.10.4]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.4
[0.10.3]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.3
[0.10.2]: https://github.com/yasyf/cookiesync/releases/tag/v0.10.2
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
