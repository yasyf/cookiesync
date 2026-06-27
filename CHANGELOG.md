# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/yasyf/cookiesync/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.1
[0.6.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.6.0
[0.5.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.5.0
[0.4.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.4.0
