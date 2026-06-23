# cookiesync

![cookiesync banner](https://github.com/yasyf/cookiesync/raw/main/docs/assets/readme-banner.webp)

[![PyPI](https://img.shields.io/pypi/v/cookiesync-cli.svg)](https://pypi.org/project/cookiesync-cli/)
[![Python](https://img.shields.io/pypi/pyversions/cookiesync-cli.svg)](https://pypi.org/project/cookiesync-cli/)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](https://github.com/yasyf/cookiesync/blob/main/LICENSE)

Sync your browser cookies across machines.

cookiesync copies the cookies your browser already holds on one machine and
replays them on another, so the sites you're signed into follow you between
laptops. It reuses your existing browser session instead of asking for
passwords again, so logins, 2FA, and SSO state carry over without you
re-authenticating anywhere.

> **macOS only.** cookiesync keeps your browser's Safe Storage key behind a
> Touch ID prompt and a Secure Enclave–bound daemon, so decrypted cookies never
> land on disk. The key helper is a Developer-ID-signed, notarized `.app`.

## Install

cookiesync publishes on PyPI as `cookiesync-cli` and installs a `cookiesync`
command. You'll reach for it often, so install it onto your PATH with
[uv](https://docs.astral.sh/uv/):

```bash
uv tool install cookiesync-cli
cookiesync --help
```

To add it to a project instead:

```bash
uv add cookiesync-cli
```

## Quickstart

```bash
# Fetch the signed key helper and start the sync daemon (one time)
cookiesync install

# Confirm the helper is installed and Developer-ID signed
cookiesync doctor

# Track a browser to sync between this Mac and another host
cookiesync browser add other-host chrome

# Hand a logged-in session to a script without giving it a password
cookiesync cookies https://example.com --browser chrome
```

Once a browser is tracked, the resident daemon watches its cookie store and
converges it across your hosts. Run `cookiesync reconcile` to force a full pass.

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

## What problems does this solve?

- A fresh machine means signing into every account again. cookiesync moves your
  live browser session over, so you land already logged in.
- 2FA and SSO re-prompt whenever you switch laptops. Carrying the existing
  cookies over keeps those sessions valid instead of restarting them.
- Built-in browser sync is all-or-nothing and locked to one vendor. cookiesync
  is browser-agnostic, and you pick which machines and which sites it touches.
- Automation needs a logged-in session but should never hold a password. Hand a
  CI job or an agent the cookies it needs instead of a credential it can leak.

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE](https://github.com/yasyf/cookiesync/blob/main/LICENSE).
