#!/usr/bin/env bash
set -euo pipefail

bin="${1:-${COOKIESYNC_BIN:?pass the cookiesync binary path or set COOKIESYNC_BIN}}"
[[ -x "$bin" ]] || { echo "FAIL binary: $bin is not executable" >&2; exit 1; }

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
