# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/yasyf/cookiesync/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.5.0
[0.4.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.4.0
