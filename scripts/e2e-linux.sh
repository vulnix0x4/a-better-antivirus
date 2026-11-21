#!/usr/bin/env bash
# End-to-end test of ABA on Linux, in the spirit of scripts/e2e.ps1: install,
# fake stealers, freeze, kill, a legitimate reader let through, resume, trust,
# release, a sweep, a hard-link trick, bait repair, uninstall, and a check
# that nothing is left behind.
#
#   scripts/e2e-linux.sh <aba binary> <grabber binary>
#
# Run it as an ordinary user with passwordless sudo on a THROWAWAY machine (CI
# does, on GitHub's ubuntu-latest): it installs a root service, plants baits
# in that user's home folder and freezes programs. Not on your own machine.
#
# Every program that reads a bait here is started through systemd-run, as the
# user: ABA freezes a stealer together with the script that started it, and
# this script would be that script.

set -uo pipefail

ABA_BIN=$(readlink -f "${1:?usage: e2e-linux.sh <aba> <grabber>}")
GRABBER=$(readlink -f "${2:?usage: e2e-linux.sh <aba> <grabber>}")
DATA=/var/lib/file-access-monitor
PROG=/usr/local/lib/file-access-monitor
UNIT=file-access-monitor.service
FROZEN=file-access-monitor.frozen
ME=$(id -un); MY_UID=$(id -u); MY_GID=$(id -g)
OUT=$(mktemp -d /tmp/aba-e2e.XXXXXX); chmod 755 "$OUT"
TOPIC="aba-e2e-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
note() { printf '   ..  %s\n' "$*"; }

diagnose() {
  printf '\n\033[31m---- service log (last 150 lines) ----\033[0m\n'
  sudo tail -n 150 "$DATA/service.log" 2>/dev/null || true
  printf '\n---- journal ----\n'
  sudo journalctl -u "$UNIT" -n 60 --no-pager 2>/dev/null || true
  printf '\n---- alerts ----\n'
  alerts 2>/dev/null | jq -c '.[] | {id, kind, tier, instant, status, title, image: .process.image, pid: .process.pid, reasons: .verdict.reasons, actions: [.actions[]? | {action, ok, detail}]}' 2>/dev/null || true
  printf '\n---- frozen group ----\n'
  cat "/sys/fs/cgroup/$FROZEN/cgroup.procs" 2>/dev/null || true
}
fail() { { printf '\n\033[31mFAILED: %s\033[0m\n' "$*"; diagnose; } >&2; cleanup_units; exit 1; }
# has PATTERN CMD...: CMD's output contains PATTERN. (Not "CMD | grep -q": with
# pipefail, grep leaving early makes the pipe count as failed.)
has() { local o; o=$("${@:2}" 2>&1) || true; grep -q -- "$1" <<<"$o"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

# ---- helpers ----
state()  { sudo cat "$DATA/state.json"; }
alerts() { sudo sh -c "cat $DATA/alerts/*.json 2>/dev/null" | jq -s 'sort_by(.id)'; }
bait_file() { state | jq -r --arg id "$1" '.baits[$id].files[0].path // empty'; }
frozen() { grep -q "$FROZEN" "/proc/$1/cgroup" 2>/dev/null; }
alive()  { [ -d "/proc/$1" ] && ! grep -q '^State:.*Z' "/proc/$1/status" 2>/dev/null; }

# launch NAME CMD...: start CMD as this user, from systemd (not from this
# script), and print its PID.
launch() {
  local name="aba-e2e-$1-$RANDOM$RANDOM"; shift
  echo "$name" >> "$OUT/units"
  sudo systemd-run --quiet --collect --unit "$name" --uid "$MY_UID" --gid "$MY_GID" \
    --setenv HOME="$HOME" --setenv USER="$ME" --working-directory "$HOME" "$@" || return 1
  local pid=0 i
  for i in $(seq 1 50); do
    pid=$(systemctl show -p MainPID --value "$name" 2>/dev/null || echo 0)
    [ "${pid:-0}" != 0 ] && break
    sleep 0.1
  done
  echo "${pid:-0}"
}
cleanup_units() {
  local u
  [ -f "$OUT/units" ] || return 0
  while read -r u; do sudo systemctl stop "$u" 2>/dev/null; done < "$OUT/units"
  : > "$OUT/units"
  return 0
}

# wait_alert JQ-CONDITION: the newest alert matching it (as JSON), within 30 s.
wait_alert() {
  local i a
  for i in $(seq 1 100); do
    a=$(alerts | jq -c "map(select($1)) | last")
    if [ -n "$a" ] && [ "$a" != null ]; then echo "$a"; return 0; fi
    sleep 0.3
  done
  return 1
}
wait_until() { local i; for i in $(seq 1 "$1"); do if "${@:2}"; then return 0; fi; sleep 0.2; done; return 1; }
has_line() { grep -q "$1" "$2" 2>/dev/null; }
field() { jq -r "$2" <<<"$1"; }
# A command that changes settings (aba trust, aba bait add) signals the
# service and returns at once; the service takes the change in a moment
# later. So: r=$(reloads); sudo aba trust ...; wait_reloaded "$r"
reloads() { sudo grep -c 'configuration reloaded' "$DATA/service.log" 2>/dev/null || true; }
reloaded_since() { [ "$(reloads)" -gt "$1" ]; }
wait_reloaded() { wait_until 75 reloaded_since "$1" || fail "the service didn't take in the new settings within 15 s"; }

# expect_frozen PID OUTFILE WHAT: an alert for PID that froze it on the spot,
# and nothing read. Prints the alert's ID.
expect_frozen() {
  local pid=$1 out=$2 what=$3 a id
  a=$(wait_alert ".process.pid == $pid") || fail "$what: no alert for pid $pid"
  id=$(field "$a" .id)
  [ "$(field "$a" .tier)" = critical ] || fail "$what: alert $id is $(field "$a" .tier), want critical: $(field "$a" '.verdict.reasons[0]')"
  [ "$(field "$a" '[.actions[]? | select(.action=="freeze" and .ok)] | length')" -ge 1 ] || fail "$what: alert $id didn't freeze: $(field "$a" '.actions | tostring')"
  [ "$(field "$a" .instant)" = true ] || fail "$what: alert $id wasn't an instant catch"
  frozen "$pid" || fail "$what: pid $pid isn't in the frozen group: $(cat /proc/$pid/cgroup 2>/dev/null)"
  if [ -n "$out" ] && has_line '^READ' "$out"; then fail "$what: it read the bait before it was frozen: $(cat "$out")"; fi
  note "$what: frozen $(field "$a" .latencyMs) ms after the open; $(field "$a" '.verdict.reasons[0]')" >&2
  echo "$id"
}

trap 'cleanup_units' EXIT

# =====================================================================
say "Before: nothing installed"
[ -e "/etc/systemd/system/$UNIT" ] && fail "ABA is already installed on this machine: this test is for a throwaway one"
command -v jq >/dev/null || fail "jq is needed"
mkdir -p "$HOME/Documents" "$HOME/Downloads"
"$ABA_BIN" --version || fail "the binary doesn't run"

# A browser that's really used, if there is one to run: ABA should plant a
# fake profile inside it, and the browser should never touch that profile.
CHROME=""
if command -v google-chrome >/dev/null; then
  timeout 60 google-chrome --headless=new --disable-gpu --no-first-run --dump-dom about:blank >/dev/null 2>&1 || true
  [ -f "$HOME/.config/google-chrome/Local State" ] && CHROME=yes
fi
note "a used Chrome profile to plant inside: ${CHROME:-no}"

# =====================================================================
say "Install"
sudo "$ABA_BIN" install --yes --preset balanced --learning 0 --ntfy-topic "$TOPIC" --auto-update=false || fail "aba install"
check "the service is running" test "$(systemctl is-active "$UNIT")" = active
check "aba is on the PATH" test "$(readlink -f /usr/local/bin/aba)" = "$PROG/aba"
check "the program belongs to root" test "$(stat -c '%U %a' "$PROG/famsvc")" = "root 755"
check "state can't be read without root" bash -c "! cat $DATA/state.json >/dev/null 2>&1"
check "alerts can't be listed without root" bash -c "! ls $DATA/alerts >/dev/null 2>&1"
check "the log can't be read without root" bash -c "! cat $DATA/service.log >/dev/null 2>&1"
check "secrets are root's alone" test "$(sudo stat -c '%U %a' "$DATA/secrets.json")" = "root 600"
wait_until 150 bash -c "aba status --once 2>/dev/null | grep -q Protected" || { aba status --once; fail "the dashboard (without root) doesn't say Protected"; }
ok "dashboard without root: Protected"
aba status --once | sed 's/^/      /'
sudo aba doctor | sed 's/^/      /'
has "Watching baits" sudo aba doctor || fail "aba doctor doesn't report on watching baits"
sudo aba status --once >/dev/null || fail "aba status as root"

say "Baits"
sudo aba bait list | sed 's/^/      /'
for id in home-passwords documents-passwords vivaldi brave electrum ssh-key git-credentials aws gcloud; do
  f=$(bait_file "$id"); [ -n "$f" ] && [ -f "$f" ] || fail "bait $id wasn't planted ($f)"
  [ "$(stat -c %U "$f")" = "$ME" ] || fail "bait $f belongs to $(stat -c %U "$f"), not $ME"
done
ok "the starter set is planted, and the files are $ME's"
check "app data is private (600)" test "$(stat -c %a "$(bait_file vivaldi)")" = 600
check "its folder too (700)" test "$(stat -c %a "$HOME/.config/vivaldi")" = 700
check "no decoy for a browser that's installed" test -z "$(bait_file chrome)"
if [ -n "$CHROME" ]; then
  check "a fake profile inside the real Chrome" test -n "$(bait_file chrome-profile)"
fi
check "the real AWS credentials file isn't faked" test ! -e "$HOME/.aws/credentials"
mapfile -t BAIT_FILES < <(state | jq -r '.baits[].files[].path')
mapfile -t BAIT_DIRS < <(state | jq -r '.baits[].createdDirs[]?')
PASSWORDS=$(bait_file home-passwords)
armed=$(state | jq -r '.health[] | select(.name=="Instant freeze") | .detail')
note "watching: $armed"

# =====================================================================
say "aba test"
sudo aba test > "$OUT/test.txt" 2>&1 || { cat "$OUT/test.txt"; fail "aba test"; }
sed 's/^/      /' "$OUT/test.txt"
grep -q "Frozen" "$OUT/test.txt" || fail "aba test didn't freeze the fake stealer"
ok "aba test caught and froze its fake stealer"

# =====================================================================
say "A fake stealer opens a bait"
install -m 755 "$GRABBER" "$HOME/Downloads/free-game"
pid=$(launch stealer "$HOME/Downloads/free-game" -child -out "$OUT/s1" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/s1" "fake stealer") || exit 1
ok "frozen inside its open, before it read anything (alert $id)"
child=$(cat "$OUT/s1.child")
check "the process it had started is frozen too" frozen "$child"
kill -CONT "$pid" 2>/dev/null; kill -CONT "$child" 2>/dev/null
check "its own user can't move it out of the frozen group" bash -c "! echo $pid > /sys/fs/cgroup/cgroup.procs 2>/dev/null"
check "nor thaw the group" bash -c "! echo 0 > /sys/fs/cgroup/$FROZEN/cgroup.freeze 2>/dev/null"
sleep 1
frozen "$pid" && ! has_line '^READ' "$OUT/s1" || fail "the stealer got going again"
ok "still frozen after SIGCONT, and it never read the bait"
wait_until 200 sudo grep -q "phone alert sent for $id" "$DATA/service.log" || fail "the phone alert for $id didn't go out"
ok "the phone alert went out (ntfy)"
sudo aba alerts | sed 's/^/      /'
sudo aba alerts show "$id" | sed 's/^/      /'
has "frozen" aba status --once || fail "the dashboard doesn't show that something is frozen"

say "aba kill"
sudo aba kill "$id" || fail "aba kill"
gone() { ! alive "$1"; }
wait_until 25 gone "$pid" || fail "pid $pid survived aba kill"
wait_until 25 gone "$child" || fail "the stealer's helper survived aba kill"
ok "the stealer and what it started are gone"

# =====================================================================
say "Legitimate readers are let through"
# An installed program (git), started by the system: a note in the history.
sudo systemd-run --quiet --wait --collect --uid "$MY_UID" --gid "$MY_GID" /usr/bin/git hash-object "$PASSWORDS" > "$OUT/git.txt" 2>&1 \
  || { cat "$OUT/git.txt"; fail "a package-owned program couldn't read the bait"; }
a=$(wait_alert '((.process.image // "") | test("/git$")) and .kind == "read"') || fail "no record of git reading the bait"
[ "$(field "$a" .tier)" = info ] || fail "git reading a bait is $(field "$a" .tier), want info: $(field "$a" '.verdict.reasons | tostring')"
[ "$(field "$a" '.actions | length')" = 0 ] || fail "ABA acted on git: $(field "$a" '.actions | tostring')"
ok "git (package-owned) read the bait: noted, not touched ($(field "$a" '.verdict.reasons | join("; ")'))"
# A file tool with nothing suspicious behind it: a warning, not a freeze.
sudo systemd-run --quiet --wait --collect --uid "$MY_UID" --gid "$MY_GID" /usr/bin/cat "$PASSWORDS" > /dev/null 2>&1 || fail "cat couldn't read the bait"
a=$(wait_alert '((.process.image // "") | test("/cat$")) and .tier == "warn"') || fail "no warning for cat reading the bait"
[ "$(field "$a" '.actions | length')" = 0 ] || fail "ABA acted on cat: $(field "$a" '.actions | tostring')"
ok "cat, started by the system: a warning, not touched ($(field "$a" '.verdict.reasons[0]'))"

say "The same tool, run by a script nobody vouches for"
cat > "$HOME/e2e-collect.sh" <<'EOF'
#!/bin/sh
cat "$1" > "$2"
sleep 300
EOF
chmod +x "$HOME/e2e-collect.sh"
launch script "$HOME/e2e-collect.sh" "$PASSWORDS" "$OUT/collected" >/dev/null || fail "couldn't start the script"
a=$(wait_alert '((.process.image // "") | test("/cat$")) and .tier == "critical"') || fail "cat run by a script from the home folder wasn't critical"
has "e2e-collect.sh" field "$a" '.verdict.reasons[0]' || fail "the reason doesn't name the script: $(field "$a" '.verdict.reasons | tostring')"
catpid=$(field "$a" .process.pid); id=$(field "$a" .id)
frozen "$catpid" || fail "cat (pid $catpid) wasn't frozen"
[ -s "$OUT/collected" ] && fail "the script got the bait's contents"
ok "frozen, and the script got nothing ($(field "$a" '.verdict.reasons[0]'))"
sudo aba kill "$id" >/dev/null || fail "aba kill"
rm -f "$HOME/e2e-collect.sh"

# =====================================================================
say "aba resume"
pid=$(launch stealer "$HOME/Downloads/free-game" -wait 2000 -out "$OUT/s2" "$PASSWORDS") || fail "couldn't start the fake stealer"
before=$(cat "/proc/$pid/cgroup")
id=$(expect_frozen "$pid" "$OUT/s2" "fake stealer") || exit 1
sudo aba resume "$id" || fail "aba resume"
wait_until 50 has_line '^DONE' "$OUT/s2" || fail "the resumed program didn't carry on: $(cat "$OUT/s2" 2>/dev/null)"
frozen "$pid" && fail "still in the frozen group after resume"
check "it's back in the control group it came from" test "$(cat "/proc/$pid/cgroup")" = "$before"
check "nothing is left on record as frozen" test "$(state | jq '.frozen | length')" = 0
kill -9 "$pid" 2>/dev/null

say "aba trust"
pid=$(launch stealer "$HOME/Downloads/free-game" -out "$OUT/s3" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/s3" "fake stealer") || exit 1
r=$(reloads)
sudo aba trust "$id" || fail "aba trust"
wait_reloaded "$r"
wait_until 50 has_line '^DONE' "$OUT/s3" || fail "the trusted program didn't carry on"
kill -9 "$pid" 2>/dev/null
count=$(alerts | jq length)
pid=$(launch stealer "$HOME/Downloads/free-game" -out "$OUT/s4" "$PASSWORDS") || fail "couldn't start it again"
wait_until 50 has_line '^DONE' "$OUT/s4" || fail "a trusted program was stopped again"
frozen "$pid" && fail "a trusted program was frozen again"
sleep 1
check "a trusted program reads that bait without a new alert" test "$(alerts | jq length)" = "$count"
kill -9 "$pid" 2>/dev/null
sudo aba ignore list | sed 's/^/      /'

say "aba release"
cp "$GRABBER" "$HOME/Downloads/other-game"; echo "different file, different fingerprint" >> "$HOME/Downloads/other-game"; chmod 755 "$HOME/Downloads/other-game"
p1=$(launch other "$HOME/Downloads/other-game" -out "$OUT/r1" "$PASSWORDS") || fail "couldn't start the fake stealer"
expect_frozen "$p1" "$OUT/r1" "first" >/dev/null || exit 1
p2=$(launch other "$HOME/Downloads/other-game" -out "$OUT/r2" "$(bait_file ssh-key)") || fail "couldn't start the fake stealer"
expect_frozen "$p2" "$OUT/r2" "second" >/dev/null || exit 1
sudo aba release || fail "aba release"
wait_until 50 has_line '^DONE' "$OUT/r1" && wait_until 50 has_line '^DONE' "$OUT/r2" || fail "aba release didn't let both run again"
check "nothing is left on record as frozen" test "$(state | jq '.frozen | length')" = 0
kill -9 "$p1" "$p2" 2>/dev/null
ok "everything frozen runs again"

# =====================================================================
say "A sweep: an installed program going through several apps' data"
pid=$(launch sweep /usr/bin/git hash-object "$(bait_file vivaldi)" "$(bait_file electrum)" "$(bait_file ssh-key)" "$(bait_file gcloud)") || fail "couldn't start git"
a=$(wait_alert ".process.pid == $pid and .tier == \"critical\"") || fail "a sweep by a package-owned program wasn't critical"
[ "$(field "$a" '.verdict.swept | length')" -ge 3 ] || fail "not reported as a sweep: $(field "$a" '.verdict | tostring')"
frozen "$pid" || fail "the sweeping program wasn't frozen"
ok "frozen at the third app's data ($(field "$a" '.verdict.swept | join(", ")'))"
sudo aba kill "$(field "$a" .id)" >/dev/null || fail "aba kill"

say "A trick: reading a bait through a hard link"
# (The link is made next to the -out file: in the home folder, on the bait's file system.)
pid=$(launch link "$HOME/Downloads/other-game" -link -out "$HOME/Downloads/e2e-l1" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$HOME/Downloads/e2e-l1" "through a hard link") || exit 1
a=$(alerts | jq -c "map(select(.id == \"$id\")) | last")
[ "$(field "$a" .verdict.evasion)" = true ] || fail "the hard link wasn't recognised as a trick: $(field "$a" '.verdict | tostring')"
ok "recognised as the bait, and as a trick ($(field "$a" '.verdict.reasons[0]'))"
sudo aba kill "$id" >/dev/null || fail "aba kill"

# =====================================================================
if [ -n "$CHROME" ]; then
  say "The real browser doesn't trip the fake profile inside it"
  count=$(alerts | jq length)
  launch chrome /usr/bin/google-chrome --headless=new --disable-gpu --no-first-run --dump-dom about:blank >/dev/null
  sleep 8
  n=$(alerts | jq '[.[] | select((.process.image // "") | test("chrome"))] | length')
  check "Chrome ran without touching its fake profile" test "$n" = 0
  check "nothing else was alerted about meanwhile" test "$(alerts | jq length)" = "$count"
fi

say "A bait that disappears is put back"
rm -f "$PASSWORDS"
sudo aba doctor --fix >/dev/null || fail "aba doctor --fix"
wait_until 150 test -f "$PASSWORDS" || fail "the deleted bait wasn't restored"
a=$(wait_alert '.kind == "bait-missing"') || fail "no alert about the deleted bait"
ok "restored, and reported ($(field "$a" .title))"
# The new file is a different file: it has to be watched too.
pid=$(launch stealer "$HOME/Downloads/other-game" -out "$OUT/s5" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/s5" "restored bait") || exit 1
ok "the restored bait is watched"
sudo aba kill "$id" >/dev/null || fail "aba kill"

# =====================================================================
say "Uninstall"
cleanup_units
sudo aba uninstall --yes --purge || fail "aba uninstall"
left=()
for p in "/etc/systemd/system/$UNIT" "$PROG" /usr/local/bin/aba "$DATA" /run/file-access-monitor "/sys/fs/cgroup/$FROZEN"; do
  [ -e "$p" ] || [ -L "$p" ] && left+=("$p")
done
for f in "${BAIT_FILES[@]}" "${BAIT_DIRS[@]}"; do [ -e "$f" ] && left+=("$f"); done
[ "${#left[@]}" = 0 ] || fail "left behind after uninstall: ${left[*]}"
ok "the service, the program, its data, the frozen group and every bait are gone"
[ "$(systemctl is-active "$UNIT" 2>/dev/null)" = active ] && fail "the service is still running"
pgrep -x famsvc >/dev/null && fail "a famsvc process is still running"
check "folders that were yours before are still there" test -d "$HOME/Documents"
ok "nothing left behind"

rm -rf "$OUT" "$HOME/Downloads/free-game" "$HOME/Downloads/other-game" "$HOME/Downloads"/e2e-l1*
printf '\n\033[32mAll end-to-end checks passed.\033[0m\n'
