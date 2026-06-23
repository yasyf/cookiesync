# cookiesync

![cookiesync banner](https://github.com/yasyf/cookiesync/raw/main/docs/assets/readme-banner.webp)

[![PyPI](https://img.shields.io/pypi/v/cookiesync-cli.svg)](https://pypi.org/project/cookiesync-cli/)
[![Python](https://img.shields.io/pypi/pyversions/cookiesync-cli.svg)](https://pypi.org/project/cookiesync-cli/)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](https://github.com/yasyf/cookiesync/blob/main/LICENSE)

Sync your browser cookies across machines — land on a new laptop already logged in.

cookiesync copies the cookies your browser already holds on one machine and replays
them on another, reusing your live session instead of asking for passwords again — so
logins, 2FA, and SSO state carry over without re-authenticating. It's browser-agnostic,
and you pick which machines and which sites it touches. Automation can borrow a
logged-in session too: hand a CI job or an agent the cookies it needs, never a password.

> **macOS only.** cookiesync keeps your browser's Safe Storage key behind a Touch ID
> prompt and a Secure Enclave–bound daemon, so decrypted cookies never land on disk.
> The key helper is a Developer-ID-signed, notarized `.app`.

## Install

Run with [uvx](https://docs.astral.sh/uv/): `uvx cookiesync --help`.

## Quickstart

```bash
# Fetch the signed key helper and install the LaunchAgents (one time)
$ cookiesync install
Installing the signed key helper via Homebrew (brew install yasyf/tap/cookiesync-keyhelper)…
Installed and verified key helper: /Applications/cookiesync-keyhelper.app
Installed cookiesync agents.

# Track a browser to sync between this Mac and another host
$ cookiesync browser add other-host chrome
Tracking other-host/chrome/Default

# Hand a logged-in session to a script — no password
$ cookiesync cookies https://example.com --browser chrome
```

Once a browser is tracked, the resident daemon watches its cookie store and converges
it across your hosts. Run `cookiesync reconcile` to force a full pass.

## Commands

| Command | What it does |
| --- | --- |
| `install` | Fetch the signed key helper, then install the LaunchAgents (watch daemon + reconcile tick). |
| `uninstall` | Remove the cookiesync LaunchAgents. |
| `doctor` | Check that the key helper is installed and Developer-ID signed. |
| `browser add/ls/rm` | Track, list, and untrack the browser profiles cookiesync syncs across hosts. |
| `watch` | Run the resident sync daemon: watch local stores and serve the RPC socket. |
| `sync --browser <name>` | Converge one browser group across this host and its peers. |
| `reconcile` | Run a full reconcile pass over every tracked browser group. |
| `auth` | Release the Safe Storage key behind one Touch ID tap and cache it for a short window. |
| `cookies <url>` | Stream a URL's cookies in the chosen format (Playwright by default). |
| `self` | Print this host's SSH target, as reposync reports it. |
| `rpc <method>` | Low-level RPC client for the resident daemon. |

Run `cookiesync --help`, or `cookiesync <command> --help`, for the full reference.

## How it works

`cookiesync install` fetches the notarized key helper and starts a resident daemon. The
daemon watches each tracked browser's cookie store, and on a change it converges that
group across your hosts over SSH — extracting and re-applying cookies through the same
RPC the peers speak. Decryption needs the browser's Safe Storage key, which the helper
releases only behind a Touch ID tap (`cookiesync auth`) and caches in the
Secure-Enclave-bound daemon for a short window, never on disk.

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE](https://github.com/yasyf/cookiesync/blob/main/LICENSE).
