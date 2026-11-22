#!/usr/bin/env bash
# End-to-end test of ABA on Linux, in the spirit of scripts/e2e.ps1: install,
# fake stealers, freeze, kill, a legitimate reader let through, resume, trust,
# release, a sweep, a hard-link trick, bait repair, uninstall, and a check
# that nothing is left behind.
#
#   scripts/e2e-linux.sh <aba binary> <grabber binary> <notifyd binary>
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
NOTIFYD=$(readlink -f "${3:?usage: e2e-linux.sh <aba> <grabber> <notifyd>}")
DATA=/var/lib/file-access-monitor
PROG=/usr/local/lib/file-access-monitor
UNIT=file-access-monitor.service
FROZEN=file-access-monitor.frozen
ME=$(id -un); MY_UID=$(id -u); MY_GID=$(id -g)
OUT=$(mktemp -d /tmp/aba-e2e.XXXXXX); chmod 755 "$OUT"
PHONE=127.0.0.1:18723   # where the stand-in for the phone listens

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
mkdir -p "$HOME/Documents" "$HOME/Downloads" "$HOME/Desktop"
"$ABA_BIN" --version || fail "the binary doesn't run"

# A browser that's really used, if there is one to run: ABA should plant a
# fake profile inside it, and the browser should never touch that profile.
CHROME=""
if command -v google-chrome >/dev/null; then
  timeout 60 google-chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$HOME/.config/google-chrome" --dump-dom about:blank >/dev/null 2>&1 || true
  [ -f "$HOME/.config/google-chrome/Local State" ] && CHROME=yes
fi
note "a used Chrome profile to plant inside: ${CHROME:-no}"
# The same for Firefox (the runner has Mozilla's build): a profile it has
# really used, listed in its profiles.ini.
FIREFOX=""; FFBIN=$(command -v firefox || true)
if [ -n "$FFBIN" ]; then
  timeout 90 "$FFBIN" --headless --screenshot "$OUT/ff.png" about:blank >/dev/null 2>&1 || true
  [ -f "$HOME/.mozilla/firefox/profiles.ini" ] && FIREFOX=yes
  [ -f "$HOME/snap/firefox/common/.mozilla/firefox/profiles.ini" ] && FIREFOX=snap
  [ -f "$HOME/.config/mozilla/firefox/profiles.ini" ] && FIREFOX=xdg
  ls -d "$HOME"/.mozilla/firefox/* "$HOME"/.config/mozilla/firefox/* "$HOME"/snap/firefox/common/.mozilla/firefox/* 2>/dev/null | sed "s/^/      /"
fi
note "a used Firefox profile to plant inside: ${FIREFOX:-no} (${FFBIN:-no firefox} -> $(readlink -f "${FFBIN:-/nonexistent}" 2>/dev/null))"

# =====================================================================
say "Install"
sudo "$ABA_BIN" install --yes --preset balanced --learning 0 --auto-update=false || fail "aba install"
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

say "Phone alerts"
# The phone is a stand-in on this machine: ntfy.sh has a daily quota per
# address, and GitHub's runners share addresses. ABA is pointed at it the way
# a self-hosted ntfy server would be set up, in its (root-only) secrets file.
sudo systemd-run --quiet --collect --unit "aba-e2e-phone" --uid "$MY_UID" --gid "$MY_GID" "$GRABBER" -serve "$PHONE" -out "$OUT/phone" || fail "couldn't start the stand-in phone"
echo aba-e2e-phone >> "$OUT/units"
printf '{"phone":{"kind":"ntfy","ntfy":{"server":"http://%s","topic":"aba-e2e"}},"canary":{}}' "$PHONE" | base64 -w0 | sudo tee "$DATA/secrets.json" >/dev/null
check "secrets are still root's alone" test "$(sudo stat -c '%U %a' "$DATA/secrets.json")" = "root 600"
r=$(reloads); sudo systemctl kill -s HUP "$UNIT" || fail "couldn't tell the service to reload"; wait_reloaded "$r"
sudo aba phone test || fail "aba phone test"
wait_until 50 has_line 'POST /aba-e2e | A Better Antivirus test alert' "$OUT/phone" || fail "the test alert didn't reach the phone: $(cat "$OUT/phone" 2>/dev/null)"
ok "aba phone test reached the phone"

say "Baits"
sudo aba bait list | sed 's/^/      /'
for id in home-passwords documents-passwords desktop-passwords backup-codes keepass vivaldi brave opera yandex metamask electrum exodus atomic telegram discord filezilla ssh-key git-credentials aws; do
  f=$(bait_file "$id"); [ -n "$f" ] && [ -f "$f" ] || fail "bait $id wasn't planted ($f)"
  [ "$(stat -c %U "$f")" = "$ME" ] || fail "bait $f belongs to $(stat -c %U "$f"), not $ME"
done
ok "the starter set is planted, and the files are $ME's"
check "app data is private (600)" test "$(stat -c %a "$(bait_file vivaldi)")" = 600
check "its folder too (700)" test "$(stat -c %a "$HOME/.config/vivaldi")" = 700
# Decoys are only for apps that aren't there. (GitHub's runners come with the
# Google Cloud SDK; a machine without it gets the fake gcloud login.)
if command -v gcloud >/dev/null || [ -e "$HOME/.config/gcloud" ]; then
  check "no fake gcloud login where gcloud is installed" test -z "$(bait_file gcloud)"
else
  check "a fake gcloud login where gcloud isn't installed" test -n "$(bait_file gcloud)"
fi
if [ -n "$CHROME" ]; then
  check "a fake profile inside the real Chrome" test -n "$(bait_file chrome-profile)"
fi
if [ -n "$FIREFOX" ]; then
  FFBAIT=firefox-profile; [ "$FIREFOX" = snap ] && FFBAIT=firefox-snap-profile; [ "$FIREFOX" = xdg ] && FFBAIT=firefox-xdg-profile
  check "a fake profile inside the real Firefox" test -n "$(bait_file $FFBAIT)"
  note "$(bait_file $FFBAIT)"
  ffdir=$(dirname "$(bait_file $FFBAIT)")
  grep -q "$(basename "$ffdir")" "$(dirname "$ffdir")/profiles.ini" && fail "the fake Firefox profile is listed in profiles.ini: Firefox would open it"
  ok "and Firefox's profiles.ini doesn't list it"
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
wait_until 25 has_line 'POST /aba-e2e | .*free-game' "$OUT/phone" || fail "the alert didn't reach the phone: $(cat "$OUT/phone" 2>/dev/null)"
ok "the phone got the alert: $(grep 'free-game' "$OUT/phone" | head -1 | cut -c1-150)"
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
timeout 60 sudo systemd-run --quiet --wait --collect --uid "$MY_UID" --gid "$MY_GID" /usr/bin/git hash-object "$PASSWORDS" > "$OUT/git.txt" 2>&1 \
  || { cat "$OUT/git.txt"; fail "a package-owned program couldn't read the bait"; }
a=$(wait_alert '((.process.image // "") | test("/git$")) and .kind == "read"') || fail "no record of git reading the bait"
[ "$(field "$a" .tier)" = info ] || fail "git reading a bait is $(field "$a" .tier), want info: $(field "$a" '.verdict.reasons | tostring')"
[ "$(field "$a" '.actions | length')" = 0 ] || fail "ABA acted on git: $(field "$a" '.actions | tostring')"
ok "git (package-owned) read the bait: noted, not touched ($(field "$a" '.verdict.reasons | join("; ")'))"
# A file tool with nothing suspicious behind it: a warning, not a freeze.
timeout 60 sudo systemd-run --quiet --wait --collect --uid "$MY_UID" --gid "$MY_GID" /usr/bin/cat "$PASSWORDS" > /dev/null 2>&1 || fail "cat couldn't read the bait"
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

say "A desktop notification, with the choices as buttons"
if [ -x /usr/bin/pkexec ] && [ -d /etc/polkit-1/rules.d ]; then
  # The runner has nobody to type a password: polkit lets this user through.
  printf 'polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.policykit.exec" && subject.user == "%s") return polkit.Result.YES;
});
' "$ME" | sudo tee /etc/polkit-1/rules.d/49-aba-e2e.rules >/dev/null
fi
# A stand-in desktop: the user's session bus, and a notification service on it
# that presses "Kill it" the way a person would.
BUS=/run/user/$MY_UID/bus
if [ ! -S "$BUS" ]; then
  launch bus /usr/bin/dbus-daemon --session --nofork --address="unix:path=$BUS" >/dev/null || fail "couldn't start a session bus"
  wait_until 50 test -S "$BUS" || fail "no session bus at $BUS"
  note "started a session bus at $BUS"
fi
launch desk /usr/bin/env DBUS_SESSION_BUS_ADDRESS="unix:path=$BUS" "$NOTIFYD" -out "$OUT/desk" -press "Kill it" >/dev/null || fail "couldn't start the stand-in desktop"
wait_until 50 has_line '^READY' "$OUT/desk" || fail "the stand-in desktop didn't start: $(sudo journalctl -n 20 --no-pager 2>/dev/null | grep -i notifyd)"
cp "$GRABBER" "$HOME/Downloads/desk-game"; echo "desktop fingerprint" >> "$HOME/Downloads/desk-game"; chmod 755 "$HOME/Downloads/desk-game"
pid=$(launch popup "$HOME/Downloads/desk-game" -out "$OUT/d1" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/d1" "fake stealer") || exit 1
wait_until 100 has_line '^NOTIFY .*desk-game' "$OUT/desk" || fail "no desktop notification: $(cat "$OUT/desk"; sudo grep 'desktop notify' "$DATA/service.log" | tail -3)"
line=$(grep '^NOTIFY .*desk-game' "$OUT/desk" | tail -1)
note "$(cut -c1-160 <<<"$line")"
grep -q "| Kill it, It's mine, Decide later$" <<<"$line" || fail "the notification doesn't offer Kill it / It's mine / Decide later: $line"
ok "the notification asks, with Windows' three choices as buttons"
wait_until 50 has_line '^PRESSED' "$OUT/desk" || fail "the stand-in desktop didn't press the button"
if [ -x /usr/bin/pkexec ] && [ -d /etc/polkit-1/rules.d ]; then
  wait_until 100 gone "$pid" || fail "pressing Kill it didn't end it: $(tail -3 "$OUT/desk"; sudo journalctl -n 30 --no-pager | grep -i -E 'pkexec|polkit|aba' | tail -8)"
  ok "pressing Kill it asked for administrator rights (pkexec) and ended the stealer"
else
  wait_until 100 has_line 'needs administrator rights' "$OUT/desk" || fail "no word on how to answer without pkexec"
  ok "without pkexec, a notification says what to type instead"
  sudo aba kill "$id" >/dev/null
fi
sudo systemctl stop 'aba-e2e-desk-*' 'aba-e2e-popup-*' 2>/dev/null  # the stand-in would press Kill it on every alert from here on

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
say "A stealer's program is cut off from the network"
# Balanced cuts a critical reader's program off. The frozen one can't do
# anything anyway; what shows the cut is the same program started again (a
# stealer's second stage, or the loot uploader), trying to reach a listener on
# this very machine: the stand-in phone.
cp "$GRABBER" "$HOME/Downloads/net-game"; echo "yet another fingerprint" >> "$HOME/Downloads/net-game"; chmod 755 "$HOME/Downloads/net-game"
p1=$(launch net "$HOME/Downloads/net-game" -out "$OUT/n1" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$p1" "$OUT/n1" "fake stealer") || exit 1
a=$(alerts | jq -c "map(select(.id == \"$id\")) | last")
[ "$(field "$a" '[.actions[]? | select(.action=="block-program" and .ok)] | length')" = 1 ] || fail "its program wasn't cut off: $(field "$a" '.actions | tostring')"
ok "the alert cut its program off ($(field "$a" '[.actions[] | select(.action=="block-program")][0].detail'))"
if command -v nft >/dev/null; then sudo nft list table inet file_access_monitor | sed 's/^/      /'; fi
p2=$(launch net2 "$HOME/Downloads/net-game" -wait 0 -connect "$PHONE" -out "$OUT/n2") || fail "couldn't start the program again"
incut() { grep -q 'file-access-monitor.blocked' "/proc/$1/cgroup" 2>/dev/null; }
wait_until 25 incut "$p2" || fail "the program started again isn't in the cut-off group: $(cat /proc/$p2/cgroup)"
wait_until 50 has_line '^NET FAIL' "$OUT/n2.net" || fail "the program started again reached the listener: $(cat "$OUT/n2.net" 2>/dev/null)"
ok "started again, it was cut off inside its exec, and can't reach a listener on this machine ($(cut -c1-90 "$OUT/n2.net"))"
check "its own user can't take it out of the cut-off group" bash -c "! echo $p2 > /sys/fs/cgroup/cgroup.procs 2>/dev/null"
if command -v nft >/dev/null; then
  check "its own user can't remove the rules" bash -c "! nft delete table inet file_access_monitor 2>/dev/null"
fi
has "Network cut-off" sudo aba doctor || fail "aba doctor doesn't report on the network cut-off"
sudo aba doctor | grep 'Network' | sed 's/^/      /'
sudo aba status --once | grep -i -E 'block|cut|internet' | sed 's/^/      /' || true
say "... and stays cut off when the service restarts"
sudo systemctl restart "$UNIT" || fail "couldn't restart the service"
before=$(cat "$OUT/n2.net")
wait_until 50 bash -c "[ \"\$(cat '$OUT/n2.net')\" != '$before' ]" || fail "the program stopped trying"
sleep 1
has_line '^NET FAIL' "$OUT/n2.net" || fail "after a service restart the program got through: $(cat "$OUT/n2.net")"
ok "still cut off after a restart ($(cut -c1-60 "$OUT/n2.net"))"
sudo aba release || fail "aba release"
wait_until 50 has_line '^NET OK' "$OUT/n2.net" || fail "after aba release the program still can't connect: $(cat "$OUT/n2.net")"
incut "$p2" && fail "after aba release it's still in the cut-off group"
ok "after aba release it reaches the listener again"
if command -v nft >/dev/null; then
  check "and ABA's firewall table is gone" bash -c "! sudo nft list table inet file_access_monitor >/dev/null 2>&1"
fi
kill -9 "$p1" "$p2" 2>/dev/null

# =====================================================================
say "A sweep: an installed program going through several apps' data"
pid=$(launch sweep /usr/bin/git hash-object "$(bait_file vivaldi)" "$(bait_file electrum)" "$(bait_file ssh-key)" "$(bait_file aws)") || fail "couldn't start git"
a=$(wait_alert ".process.pid == $pid and .tier == \"critical\"") || fail "a sweep by a package-owned program wasn't critical"
[ "$(field "$a" '.verdict.swept | length')" -ge 3 ] || fail "not reported as a sweep: $(field "$a" '.verdict | tostring')"
frozen "$pid" || fail "the sweeping program wasn't frozen"
ok "frozen at the third app's data ($(field "$a" '.verdict.swept | join(", ")'))"
sudo aba kill "$(field "$a" .id)" >/dev/null || fail "aba kill"

say "A scheduled backup, trusted by its exact command"
# tar of several apps' data, started by the system (as a timer would): a
# sweep, frozen. Trusted from the alert, that exact command runs from then on;
# the same words from a script nobody vouches for are still a stealer.
BACKUP=(/usr/bin/tar cf "$OUT/backup.tar" "$(bait_file vivaldi)" "$(bait_file electrum)" "$(bait_file ssh-key)" "$(bait_file aws)")
# It runs with the PATH cron gives a job: with a folder others can write to on
# its PATH, tar could be made to run a helper planted there (gzip, for one),
# so a command started that way isn't trusted (the runner has such a folder).
pid=$(launch backup /usr/bin/env PATH=/usr/bin:/bin "${BACKUP[@]}") || fail "couldn't start tar"
a=$(wait_alert ".process.pid == $pid and .tier == \"critical\"") || fail "a backup-like sweep by tar wasn't caught"
id=$(field "$a" .id)
r=$(reloads)
sudo aba trust "$id" > "$OUT/trust.txt" 2>&1 || { cat "$OUT/trust.txt"; fail "aba trust on the sweep"; }
sed 's/^/      /' "$OUT/trust.txt"
wait_reloaded "$r"
sudo aba ignore list | grep -q "run in $HOME" || fail "the rule isn't pinned to the folder: $(sudo aba ignore list)"
count=$(alerts | jq length)
rm -f "$OUT/backup.tar"
timeout 60 sudo systemd-run --quiet --wait --collect --uid "$MY_UID" --gid "$MY_GID" --setenv HOME="$HOME" --setenv PATH=/usr/bin:/bin --working-directory "$HOME" "${BACKUP[@]}" \
  || fail "the trusted backup was stopped: $(alerts | jq -c "last | {tier, reasons: .verdict.reasons, cmd: .process.commandLine, dir: .process.dir}"); rules: $(sudo aba ignore list); $(sudo grep "trust rule" $DATA/service.log | tail -3)"
test -s "$OUT/backup.tar" || fail "the trusted backup didn't write its archive"
sleep 1
check "the trusted backup ran without a new alert" test "$(alerts | jq length)" = "$count"
printf '#!/bin/sh\n%s\nsleep 300\n' "$(printf '%q ' "${BACKUP[@]}")" > "$HOME/Downloads/replay.sh"; chmod +x "$HOME/Downloads/replay.sh"
launch replay "$HOME/Downloads/replay.sh" >/dev/null || fail "couldn't start the replay"
a=$(wait_alert '((.process.image // "") | test("/tar$")) and .tier == "critical" and (.verdict.reasons | join(" ") | test("replay.sh"))') \
  || fail "the backup's exact words, run by a script from Downloads, weren't caught"
ok "the same words from a script nobody vouches for: frozen ($(field "$a" '[.verdict.reasons[] | select(test("replay.sh"))][0]' | cut -c1-110))"
sudo aba kill "$(field "$a" .id)" >/dev/null
rm -f "$HOME/Downloads/replay.sh"


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
  launch chrome /usr/bin/google-chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$HOME/.config/google-chrome" --dump-dom about:blank >/dev/null
  sleep 8
  n=$(alerts | jq '[.[] | select((.process.image // "") | test("chrome"))] | length')
  check "Chrome ran without touching its fake profile" test "$n" = 0
  check "nothing else was alerted about meanwhile" test "$(alerts | jq length)" = "$count"
fi

if [ -n "$FIREFOX" ]; then
  say "The real Firefox doesn't trip the fake profile inside it"
  count=$(alerts | jq length)
  launch firefox "$FFBIN" --headless --screenshot "$OUT/ff2.png" about:blank >/dev/null
  sleep 15
  n=$(alerts | jq '[.[] | select((.process.image // "") | test("firefox"))] | length')
  check "Firefox ran without touching its fake profile" test "$n" = 0
  check "nothing else was alerted about meanwhile" test "$(alerts | jq length)" = "$count"
fi

say "A bait that disappears is put back at once, and whoever did it is named"
pid=$(launch deleter "$HOME/Downloads/other-game" -delete -out "$OUT/del" "$PASSWORDS") || fail "couldn't start the deleter"
wait_until 50 has_line '^DELETED' "$OUT/del" || fail "the deleter didn't delete the bait: $(cat "$OUT/del" 2>/dev/null)"
wait_until 25 test -f "$PASSWORDS" || fail "the deleted bait wasn't put back within 5 s"
a=$(wait_alert ".kind == \"delete\" and .process.pid == $pid") || fail "no alert naming who deleted the bait"
ok "put back within moments, and the alert names $(field "$a" '.process.image') (pid $pid): $(field "$a" .title)"
kill -9 "$pid" 2>/dev/null
echo "not the bait" > "$HOME/.e2e-swap"; mv "$HOME/.e2e-swap" "$PASSWORDS" || fail "couldn't rename a file over the bait"
wait_until 50 bash -c "[ \$(sudo sh -c 'cat $DATA/alerts/*.json' | jq -s '[.[] | select(.kind==\"delete\")] | length') -ge 2 ]" || fail "a bait replaced by a rename over it wasn't reported"
ok "replaced by a rename over it: reported"
# What was renamed over it is somebody's file now, which ABA never deletes (not
# even when it's uninstalled): take it away, and ABA plants its bait again.
rm -f "$PASSWORDS"; wait_until 25 test -f "$PASSWORDS" || fail "the bait wasn't planted again after the file put in its place was deleted"
grep -q "not the bait" "$PASSWORDS" && fail "the file put in the bait's place came back instead of the bait"
VIV=$(bait_file vivaldi); mv "$HOME/.config/vivaldi" "$HOME/.config/vivaldi-moved" || fail "couldn't move the fake Vivaldi folder"
wait_until 25 test -f "$VIV" || fail "a folder of baits renamed away wasn't put back"
ok "a folder of baits renamed away: put back"
rm -rf "$HOME/.config/vivaldi-moved"
# The new file is a different file: it has to be watched too.
pid=$(launch stealer "$HOME/Downloads/other-game" -out "$OUT/s5" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/s5" "restored bait") || exit 1
ok "the restored bait is watched"
sudo aba kill "$id" >/dev/null || fail "aba kill"

# =====================================================================
say "Strict: isolating the machine, with the phone alert still getting out"
# A phone that isn't on this machine's loopback (which isolation leaves
# alone): a server in a network namespace of its own, over a veth pair.
NS=aba-e2e-phone; PHONE2=10.203.0.2:18724
sudo ip netns add "$NS" && sudo ip link add aba-e2e-h type veth peer name aba-e2e-p && sudo ip link set aba-e2e-p netns "$NS" \
  && sudo ip addr add 10.203.0.1/24 dev aba-e2e-h && sudo ip link set aba-e2e-h up \
  && sudo ip netns exec "$NS" ip addr add 10.203.0.2/24 dev aba-e2e-p && sudo ip netns exec "$NS" ip link set aba-e2e-p up \
  && sudo ip netns exec "$NS" ip link set lo up || fail "couldn't set up the network namespace for the second phone"
sudo systemd-run --quiet --collect --unit aba-e2e-phone2 ip netns exec "$NS" "$GRABBER" -serve "$PHONE2" -out "$OUT/phone2" || fail "couldn't start the second phone"
echo aba-e2e-phone2 >> "$OUT/units"
reach2() { curl -s -m 2 -o /dev/null "http://$PHONE2/probe"; }
wait_until 50 reach2 || fail "the second phone can't be reached before isolation"
printf '{"phone":{"kind":"ntfy","ntfy":{"server":"http://%s","topic":"aba-e2e"}},"canary":{}}' "$PHONE2" | base64 -w0 | sudo tee "$DATA/secrets.json" >/dev/null
sudo jq '.responses.critical = ["freeze","block-program","isolate"] | .preset = "strict"' "$DATA/config.json" | sudo tee "$DATA/config.json.new" >/dev/null \
  && sudo mv "$DATA/config.json.new" "$DATA/config.json" && sudo chmod 600 "$DATA/config.json" || fail "couldn't switch to strict"
r=$(reloads); sudo systemctl kill -s HUP "$UNIT" || fail "couldn't tell the service to reload"; wait_reloaded "$r"
pid=$(launch iso "$HOME/Downloads/other-game" -out "$OUT/i1" "$PASSWORDS") || fail "couldn't start the fake stealer"
id=$(expect_frozen "$pid" "$OUT/i1" "fake stealer, strict") || exit 1
a=$(alerts | jq -c "map(select(.id == \"$id\")) | last")
[ "$(field "$a" '[.actions[]? | select(.action=="isolate" and .ok)] | length')" = 1 ] || fail "the machine wasn't isolated: $(field "$a" '.actions | tostring')"
ok "isolated by alert $id"
# From here on new connections fail: release first if anything goes wrong.
release_net() { sudo "$ABA_BIN" release >/dev/null 2>&1; sudo nft delete table inet file_access_monitor 2>/dev/null; return 0; }
trap 'release_net; cleanup_units; sudo ip netns del aba-e2e-phone 2>/dev/null' EXIT
reach2 && { release_net; fail "a program of the user's reached the second phone while the machine is isolated"; }
ok "a program of the user's can't open a connection out"
wait_until 100 has_line "POST /aba-e2e | .*other-game" "$OUT/phone2" || { release_net; fail "the phone alert didn't get out of the isolated machine: $(cat "$OUT/phone2" 2>/dev/null)"; }
ok "but ABA's own phone alert did: $(grep other-game "$OUT/phone2" | head -1 | cut -c1-120)"
has "isolated" aba status --once || { release_net; fail "the dashboard doesn't say the machine is isolated"; }
sudo aba doctor | grep -i -E 'isolat|network' | sed 's/^/      /'
sudo systemctl restart "$UNIT" || { release_net; fail "couldn't restart the service"; }
wait_until 75 bash -c "systemctl is-active -q $UNIT" || { release_net; fail "the service didn't come back"; }
sleep 1
reach2 && { release_net; fail "after a service restart the machine isn't isolated any more"; }
ok "still isolated after the service restarted"
sudo aba release || { release_net; fail "aba release"; }
wait_until 50 reach2 || fail "after aba release the second phone still can't be reached"
ok "aba release: the network is back"
trap 'cleanup_units' EXIT
sudo ip netns del "$NS" 2>/dev/null

# =====================================================================
say "Updating in place, and rolling back a version that doesn't start"
# What `aba update` and the automatic updates do once a signed release is
# downloaded and checked: stop the service, swap the program, start it, and
# put the old one back if the new one doesn't come up.
aba update --check 2>&1 | sed 's/^/      /'
UPD=$PROG/updates
sudo install -d -m 700 "$UPD" && sudo install -m 755 "$ABA_BIN" "$UPD/aba-vtest.exe" || fail "couldn't stage an update"
sudo "$PROG/aba" update apply --file "$UPD/aba-vtest.exe" --from e2e || fail "aba update apply"
check "the service runs the updated program" test "$(systemctl is-active "$UNIT")" = active
printf '#!/bin/sh\nexit 1\n' | sudo tee "$UPD/aba-broken.exe" >/dev/null && sudo chmod 755 "$UPD/aba-broken.exe"
sudo "$PROG/aba" update apply --file "$UPD/aba-broken.exe" --from e2e 2>&1 | sed 's/^/      /'
wait_until 100 bash -c "systemctl is-active -q $UNIT" || fail "after a failed update the service isn't running"
check "the program that didn't start was rolled back" cmp -s "$PROG/famsvc" "$ABA_BIN"
check "and the CLI too" cmp -s "$PROG/aba" "$ABA_BIN"
ok "a version that doesn't start was rolled back, and protection carried on"

# =====================================================================
say "Uninstall"
cleanup_units
sudo aba uninstall --yes --purge || fail "aba uninstall"
left=()
for p in "/etc/systemd/system/$UNIT" "$PROG" /usr/local/bin/aba "$DATA" /run/file-access-monitor "/sys/fs/cgroup/$FROZEN" /sys/fs/cgroup/file-access-monitor.blocked; do
  [ -e "$p" ] || [ -L "$p" ] && left+=("$p")
done
for f in "${BAIT_FILES[@]}" "${BAIT_DIRS[@]}"; do [ -e "$f" ] && left+=("$f"); done
[ "${#left[@]}" = 0 ] || fail "left behind after uninstall: ${left[*]}"
ok "the service, the program, its data, the frozen group and every bait are gone"
[ "$(systemctl is-active "$UNIT" 2>/dev/null)" = active ] && fail "the service is still running"
pgrep -x famsvc >/dev/null && fail "a famsvc process is still running"
check "folders that were yours before are still there" test -d "$HOME/Documents"
if command -v nft >/dev/null; then sudo nft list table inet file_access_monitor >/dev/null 2>&1 && fail "ABA's firewall table is still there after uninstall"; fi
ok "nothing left behind"

sudo rm -f /etc/polkit-1/rules.d/49-aba-e2e.rules
rm -rf "$OUT" "$HOME/Downloads/free-game" "$HOME/Downloads/other-game" "$HOME/Downloads/net-game" "$HOME/Downloads/desk-game" "$HOME/Downloads"/e2e-l1*
printf '\n\033[32mAll end-to-end checks passed.\033[0m\n'
