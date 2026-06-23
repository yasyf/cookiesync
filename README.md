# cookiesync

![cookiesync banner](https://github.com/yasyf/cookiesync/raw/main/docs/assets/readme-banner.webp)

[![PyPI](https://img.shields.io/pypi/v/cookiesync.svg)](https://pypi.org/project/cookiesync/)
[![Python](https://img.shields.io/pypi/pyversions/cookiesync.svg)](https://pypi.org/project/cookiesync/)
[![Docs](https://img.shields.io/github/actions/workflow/status/yasyf/cookiesync/docs.yml?branch=main&label=docs)](https://yasyf.github.io/cookiesync/)
[![License: PolyForm-Noncommercial-1.0.0](https://img.shields.io/badge/License-PolyForm-Noncommercial-1.0.0-blue.svg)](https://github.com/yasyf/cookiesync/blob/main/LICENSE)

Sync your browser cookies across machines.

cookiesync copies the cookies your browser already holds on one machine and
replays them on another, so the sites you're signed into follow you between
laptops. It reuses your existing browser session instead of asking for
passwords again, so logins, 2FA, and SSO state carry over without you
re-authenticating anywhere.

## Install

No install needed — run everything through [uvx](https://docs.astral.sh/uv/):

```bash
uvx cookiesync --help
```

`uvx` fetches cookiesync into a throwaway environment and runs it. To add it
to a project instead:

```bash
uv add cookiesync
```

## Quickstart

Check that the CLI runs:

```bash
$ uvx cookiesync hello
Hello from cookiesync!
```

That's the starter command. The sync commands land next; see the
[docs](https://yasyf.github.io/cookiesync/) for the current surface.

## What problems does this solve?

- A fresh machine means signing into every account again. cookiesync moves your
  live browser session over, so you land already logged in.
- 2FA and SSO re-prompt whenever you switch laptops. Carrying the existing
  cookies over keeps those sessions valid instead of restarting them.
- Built-in browser sync is all-or-nothing and locked to one vendor. cookiesync
  is browser-agnostic, and you pick which machines and which sites it touches.
- Automation needs a logged-in session but should never hold a password. Hand a
  CI job or an agent the cookies it needs instead of a credential it can leak.

## Docs

[Read the docs](https://yasyf.github.io/cookiesync/) for the full guide and API reference.
