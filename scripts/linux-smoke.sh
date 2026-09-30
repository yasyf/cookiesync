#!/usr/bin/env bash
set -euo pipefail

bin="${1:-${COOKIESYNC_BIN:?pass the cookiesync binary path or set COOKIESYNC_BIN}}"
[[ -x "$bin" ]] || { echo "FAIL binary: $bin is not executable" >&2; exit 1; }
fixtures="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/internal/cookie/testdata"
if [[ -n "${COOKIESYNC_SMOKE_CHROME+set}" ]]; then
  [[ -x "$COOKIESYNC_SMOKE_CHROME" ]] || { echo "FAIL chrome: COOKIESYNC_SMOKE_CHROME='$COOKIESYNC_SMOKE_CHROME' is not executable" >&2; exit 1; }
  PATH="$(dirname "$COOKIESYNC_SMOKE_CHROME"):$PATH"
fi

root="$(mktemp -d /tmp/cs-smoke.XXXXXX)"
export HOME="$root/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_RUNTIME_DIR="$root/run"
export DAEMONKIT_HOME="$root/dk"
export COOKIESYNC_CONFIG_DIR="$XDG_CONFIG_HOME/cookiesync"
unset COOKIESYNC_REQUESTOR CLAUDE_CODE_SESSION_ID
mkdir -p "$HOME" "$XDG_CONFIG_HOME/synckit" "$COOKIESYNC_CONFIG_DIR" "$XDG_RUNTIME_DIR" "$DAEMONKIT_HOME"
chmod 0700 "$root" "$HOME" "$XDG_CONFIG_HOME/synckit" "$COOKIESYNC_CONFIG_DIR" "$XDG_RUNTIME_DIR" "$DAEMONKIT_HOME"

supervisor=""
failures=0
chrome_pattern='(google-chrome|chromium|/chrome/chrome)( |$)'
resident_pattern='(helper-serve|cookiesync supervise)'

pass() { echo "PASS $*"; }
fail() {
  echo "FAIL $*" >&2
  failures=$((failures + 1))
}

absent() {
  local s=0
  pgrep -f -- "$1" >/dev/null || s=$?
  case $s in
    1) return 0 ;;
    0) return 1 ;;
    *) fail "pgrep exited $s"; return 1 ;;
  esac
}

teardown() {
  "$bin" uninstall >/dev/null 2>&1 || true
  if [[ -n "$supervisor" ]] && kill -0 "$supervisor" 2>/dev/null; then
    kill -TERM "$supervisor" 2>/dev/null || true
    wait "$supervisor" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap teardown EXIT

expect_eq() {
  if [[ "$3" == "$2" ]]; then
    pass "$1"
  else
    fail "$1: got '$3', want '$2'"
  fi
}

expect_closed() {
  local name="$1" status
  shift
  set +e
  "$bin" "$@" >"$root/stdout" 2>"$root/stderr"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    fail "$name: exited 0, want a non-zero fail-closed exit"
  elif [[ -s "$root/stdout" ]]; then
    fail "$name: exited $status but wrote $(wc -c <"$root/stdout") bytes to stdout, want none"
  else
    pass "$name: exit $status, empty stdout ($(head -c 200 "$root/stderr" | tr '\n' ' '))"
  fi
}

expect_served() {
  local name="$1" want="$2" status
  shift 2
  set +e
  "$bin" "$@" >"$root/stdout" 2>"$root/stderr"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    fail "$name: exit $status, want 0 ($(head -c 200 "$root/stderr" | tr '\n' ' '))"
  elif [[ "$(<"$root/stdout")" != "$want" ]]; then
    fail "$name: stdout '$(head -c 300 "$root/stdout")', want '$want'"
  else
    pass "$name"
  fi
}

printf '%s\n' '{"host_registry":{"self":"agent@vm","hosts":[]},"schema":{"identity":"synckit-state-v1","version":1,"fingerprint":"2dc96a8a0930930535e711cbab04af029573c9b95318206f8a8fbad87677ca38"},"synckit":{}}' \
  >"$XDG_CONFIG_HOME/synckit/state.json"
chmod 0600 "$XDG_CONFIG_HOME/synckit/state.json"
pass "standalone host: synckit registry self=agent@vm, no peers"

out="$(COOKIESYNC_REQUESTOR=smoke-token-1 "$bin" requestor)"
expect_eq "requestor: COOKIESYNC_REQUESTOR verbatim" "smoke-token-1" "$out"
out="$(CLAUDE_CODE_SESSION_ID=a3283ae1-0000-4000-8000-000000000000 "$bin" requestor)"
expect_eq "requestor: Claude session form" "Claude Code · a3283ae1" "$out"
first="$(COOKIESYNC_REQUESTOR=smoke-stable "$bin" requestor)"
out="$(COOKIESYNC_REQUESTOR=smoke-stable "$bin" requestor)"
expect_eq "requestor: token stable across two invocations" "$first" "$out"
bare="$("$bin" requestor)"
if [[ "$bare" =~ ^pid-[1-9][0-9]*$ ]]; then
  pass "requestor: bare form falls back to the parent pid ($bare)"
else
  fail "requestor: bare form gave '$bare', want pid-<ppid>"
fi

setsid "$bin" supervise >"$root/supervise.log" 2>&1 &
supervisor=$!
installed=""
for _ in $(seq 1 50); do
  if installed="$("$bin" install 2>"$root/install.err")"; then
    break
  fi
  installed=""
  sleep 0.2
done
if [[ "$installed" == "Resident helper serving under 'cookiesync supervise' (started)." ]]; then
  pass "install: helper ensured under the supervisor"
else
  fail "install: got '$installed' ($(tr '\n' ' ' <"$root/install.err")), want the started line"
  sed 's/^/  supervise| /' "$root/supervise.log" >&2
fi

set +e
doctor="$("$bin" doctor 2>&1)"
set -e
printf '%s\n' "$doctor" | sed 's/^/  doctor| /'
for line in "OK   supervisor" "OK   helper socket" "OK   key cache: in process memory only"; do
  if grep -qF "$line" <<<"$doctor"; then
    pass "doctor: '$line'"
  else
    fail "doctor: missing '$line'"
  fi
done
if grep -qiE 'enclave|touch id|keychain' <<<"$doctor"; then
  fail "doctor: names a Mac key backend on Linux"
else
  pass "doctor: no Secure Enclave, Touch ID or Keychain wording"
fi

mkdir -p "$XDG_CONFIG_HOME/google-chrome/Default"
: >"$XDG_CONFIG_HOME/google-chrome/Default/Cookies"
pass "profile: empty synthetic chrome Default store, no real cookies"

expect_closed "auth --reason smoke" auth --reason smoke
for format in playwright webstorage header; do
  expect_closed "cookies --format $format" cookies --format "$format" -- example.com
done
expect_closed "bridge open --json" bridge open --json
if grep -qF "no peer has a live session to approve consent" "$root/stderr"; then
  pass "bridge open: bare target reached consent routing with no live approver"
else
  fail "bridge open: stderr missing 'no peer has a live session to approve consent'"
fi
expect_closed "bridge stop" bridge stop
if grep -qF "no saved bridge for :chrome:Default" "$root/stderr"; then
  pass "bridge stop: bare target resolved to :chrome:Default with nothing to stop"
else
  fail "bridge stop: stderr '$(tr '\n' ' ' <"$root/stderr")' does not name :chrome:Default"
fi
if absent "$chrome_pattern"; then
  pass "bridge: no Chrome process running"
else
  fail "bridge: Chrome still running: $(pgrep -a -f -- "$chrome_pattern" | cut -c1-120 | tr '\n' ';')"
fi

pw="$fixtures/import_playwright.json"
ws="$fixtures/import_webstorage.json"
flags=(--browser chrome --profile Default)

expect_closed "import: refuses a document reaching past the named hosts" import --format playwright --ttl 2m "${flags[@]}" -- app.example.test <"$pw"
if grep -qF "is sent to none of the named hosts" "$root/stderr"; then
  pass "import: refusal names a cookie sent to none of the named hosts"
else
  fail "import: stderr '$(tr '\n' ' ' <"$root/stderr")' does not say 'is sent to none of the named hosts'"
fi
expect_closed "import: --ttl 25h is refused" import --format playwright --ttl 25h "${flags[@]}" -- app.example.test www.other.test api.third.test <"$pw"
if grep -qF "outside 1s..24h" "$root/stderr"; then
  pass "import: refusal names the 1s..24h ttl bound"
else
  fail "import: stderr '$(tr '\n' ' ' <"$root/stderr")' does not say 'outside 1s..24h'"
fi
expect_closed "cookies: still fail closed after refused imports" cookies --format header -- app.example.test

expect_served "import: playwright document held in memory" "imported 3 cookie(s) and 1 origin(s) into chrome/Default for api.third.test, app.example.test, www.other.test (expires in 2m0s)" import --format playwright --ttl 2m "${flags[@]}" -- app.example.test www.other.test api.third.test <"$pw"
expect_served "cookies header from the import" "sid=synthetic-session" cookies --format header -- app.example.test
expect_served "cookies header, second named host" "pref=dark" cookies --format header -- www.other.test
expect_served "cookies playwright from the import" '{"cookies": [{"name": "sid", "value": "synthetic-session", "domain": "app.example.test", "path": "/", "expires": -1, "httpOnly": true, "secure": true, "sameSite": "Lax"}], "origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}]}]}' cookies --format playwright -- app.example.test
expect_served "cookies webstorage from a playwright import" '{"origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}], "sessionStorage": []}]}' cookies --format webstorage -- app.example.test
expect_served "cookies --browser chrome from the import" "sid=synthetic-session" cookies "${flags[@]}" --format header -- app.example.test
expect_closed "cookies outside the import scope fail closed" cookies --format header -- sub.app.example.test
expect_closed "cookies mixing imported and foreign hosts fail closed" cookies --format header -- app.example.test example.com

if [[ -n "${COOKIESYNC_SMOKE_CHROME+set}" ]]; then
  set +e
  "$bin" bridge open --json >"$root/stdout" 2>"$root/stderr"
  status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    fail "bridge open --json from the import: exit $status, want 0 ($(head -c 200 "$root/stderr" | tr '\n' ' '))"
  elif ! grep -qF '"url": "ws://127.0.0.1:' "$root/stdout"; then
    fail "bridge open --json from the import: stdout '$(head -c 300 "$root/stdout" | tr '\n' ' ')' has no ws://127.0.0.1 url"
  elif ! grep -qF '"endpoint": "agent@vm:chrome:Default"' "$root/stdout"; then
    fail "bridge open --json from the import: stdout '$(head -c 300 "$root/stdout" | tr '\n' ' ')' does not name agent@vm:chrome:Default"
  elif ! jq -e '.expires_in > 0 and .expires_in <= 120' "$root/stdout" >/dev/null; then
    fail "bridge open --json from the import: expires_in $(jq .expires_in "$root/stdout"), want 0 < expires_in <= 120"
  else
    pass "bridge open --json from the import: ws url, agent@vm:chrome:Default, expires_in $(jq .expires_in "$root/stdout") capped by the 2m import"
  fi
  expect_served "bridge stop after an import-seeded open" "bridge closed · :chrome:Default" bridge stop
  gone=""
  for _ in $(seq 1 25); do
    if absent "$chrome_pattern"; then
      gone=1
      break
    fi
    sleep 0.2
  done
  if [[ -n "$gone" ]]; then
    pass "bridge stop after an import-seeded open: no Chrome process running"
  else
    fail "bridge stop after an import-seeded open: Chrome still running: $(pgrep -a -f -- "$chrome_pattern" | cut -c1-120 | tr '\n' ';')"
  fi
else
  echo "SKIP bridge open from import: COOKIESYNC_SMOKE_CHROME unset"
fi

expect_served "import: webstorage document replaces the playwright one" "imported 0 cookie(s) and 2 origin(s) into chrome/Default for app.example.test (expires in 2m0s)" import --format webstorage --ttl 2m "${flags[@]}" -- app.example.test <"$ws"
expect_served "cookies webstorage carries sessionStorage" "$(<"$ws")" cookies --format webstorage -- app.example.test
expect_served "cookies playwright after the replacement has no cookies" '{"cookies": [], "origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}]}]}' cookies --format playwright -- app.example.test
expect_served "import: one-second ttl" "imported 0 cookie(s) and 2 origin(s) into chrome/Default for app.example.test (expires in 1s)" import --format webstorage --ttl 1s "${flags[@]}" -- app.example.test <"$ws"
sleep 2
expect_closed "cookies after the import's ttl lapses fail closed" cookies --format webstorage -- app.example.test

out="$("$bin" uninstall)"
expect_eq "uninstall: helper stopped" "Stopped the resident helper; 'cookiesync supervise' no longer runs it." "$out"
kill -TERM "$supervisor"
wait "$supervisor" 2>/dev/null || true
supervisor=""
sleep 1
if absent "$resident_pattern"; then
  pass "teardown: no cookiesync supervisor or helper process survives"
else
  fail "teardown: surviving processes: $(pgrep -a -f -- "$resident_pattern" | tr '\n' ';')"
fi
if absent "$chrome_pattern"; then
  pass "teardown: no Chrome process survives"
else
  fail "teardown: Chrome survives teardown"
fi

if [[ $failures -ne 0 ]]; then
  echo "linux smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "linux smoke: all checks passed"
