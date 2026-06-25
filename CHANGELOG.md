# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/yasyf/cookiesync/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/yasyf/cookiesync/releases/tag/v0.4.0
