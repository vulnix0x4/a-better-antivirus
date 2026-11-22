#!/usr/bin/env bash
# End-to-end test of ABA on macOS, in the spirit of scripts/e2e-linux.sh:
# install as a launchd daemon, Full Disk Access, fake stealers frozen, kill, a
# tool let through, resume, trust, release, a sweep, a hard-link trick, a copy
# made through Finder, Strict mode's isolation, uninstall, and a check that
# nothing is left behind.
#
#   scripts/e2e-macos.sh <aba binary> <grabber binary>
#
# Run it as an ordinary user with passwordless sudo on a THROWAWAY Mac (CI
# does, on GitHub's macOS runners): it installs a root daemon, writes to the
# privacy database to give it Full Disk Access (that needs System Integrity
# Protection off, as it is on the runners), plants baits in that user's home
# folder, freezes programs and cuts the network for a moment. Not on your own
# Mac.
#
# Every program that reads a bait is started detached from this script (its
# parent is launchd): ABA freezes a stealer together with the script that
# started it, and this script would be that script.

set -uo pipefail

abs() { (cd "$(dirname "$1")" && echo "$(pwd)/$(basename "$1")"); }
ABA_BIN=$(abs "${1:?usage: e2e-macos.sh <aba> <grabber>}")
GRABBER=$(abs "${2:?usage: e2e-macos.sh <aba> <grabber>}")
SUPPORT="/Library/Application Support/File Access Monitor"
DATA="$SUPPORT/Data"
PROG="$SUPPORT/File Access Monitor.app/Contents/MacOS"
LABEL=com.fileaccessmonitor.service
PLIST=/Library/LaunchDaemons/$LABEL.plist
ANCHOR=com.apple/250.FileAccessMonitor
TCCDB="/Library/Application Support/com.apple.TCC/TCC.db"
ME=$(id -un)
OUT=$(mktemp -d /tmp/aba-e2e.XXXXXX); chmod 755 "$OUT"
PHONE=127.0.0.1:18723   # where the stand-in for the phone listens

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
note() { printf '   ..  %s\n' "$*"; }

diagnose() {
  printf '\n\033[31m---- service log (last 150 lines) ----\033[0m\n'
  sudo tail -n 150 "$DATA/service.log" 2>/dev/null || true
  printf '\n---- crash log ----\n'
  sudo tail -n 40 "$DATA/crash.log" 2>/dev/null || true
  printf '\n---- launchd ----\n'
  launchctl print "system/$LABEL" 2>/dev/null | grep -E '^\s*(state|pid|last exit code|runs) =' || true
  printf '\n---- alerts ----\n'
  alerts 2>/dev/null | jq -c '.[] | {id, kind, tier, status, title, image: .process.image, pid: .process.pid, reasons: .verdict.reasons, actions: [.actions[]? | {action, ok, detail}]}' 2>/dev/null || true
}
fail() { { printf '\n\033[31mFAILED: %s\033[0m\n' "$*"; diagnose; } >&2; cleanup; exit 1; }
has() { local o; o=$("${@:2}" 2>&1) || true; grep -q -- "$1" <<<"$o"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else fail "$what"; fi; }

# ---- helpers ----
state()  { sudo cat "$DATA/state.json"; }
alerts() { sudo sh -c "cat '$DATA'/alerts/*.json 2>/dev/null" | jq -s 'sort_by(.id)'; }
bait_file() { state | jq -r --arg id "$1" '.baits[$id].files[0].path // empty'; }
alive()  { kill -0 "$1" 2>/dev/null && [ "$(ps -o stat= -p "$1" | tr -d ' ')" != Z ]; }
gone()   { ! alive "$1"; }
ticks()  { if [ -f "$1.tick" ]; then wc -l < "$1.tick" | tr -d ' '; else echo 0; fi; }
# frozen OUT: the grabber writing OUT isn't getting anywhere: no new tick in
# 1.5 s, even after its own user tells it to carry on.
frozen() {
  local out=$1 pid a b
  pid=$(cat "$out.pid")
  kill -CONT "$pid" 2>/dev/null
  a=$(ticks "$out"); sleep 1.5; b=$(ticks "$out")
  [ "$a" = "$b" ] && alive "$pid"
}
running() { local a b; a=$(ticks "$1"); sleep 1; b=$(ticks "$1"); [ "$b" -gt "$a" ]; }

PIDS=()
# launch CMD...: start CMD as this user, detached (launchd becomes its
# parent), and print its PID.
launch() {
  local pf="$OUT/launch.$RANDOM$RANDOM"
  ( "$@" > "$pf.log" 2>&1 < /dev/null & echo $! > "$pf" )
  local pid; pid=$(cat "$pf"); PIDS+=("$pid"); ln -sf "$pf.log" "$OUT/output.$pid"; echo "$pid"
}
# output PID: what a launched program printed.
output() { cat "$OUT/output.$1" 2>/dev/null | tail -20 | sed 's/^/      | /'; }
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && sudo kill -9 "$p" 2>/dev/null; done
  sudo pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true
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
reloads() { sudo grep -c 'configuration reloaded' "$DATA/service.log" 2>/dev/null || true; }
reloaded_since() { [ "$(reloads)" -gt "$1" ]; }
wait_reloaded() { wait_until 75 reloaded_since "$1" || fail "the service didn't take in the new settings within 15 s"; }
service_pid() { launchctl print "system/$LABEL" 2>/dev/null | awk '/^\tpid = /{print $3}'; }

# expect_frozen PID OUT WHAT: a critical alert for PID that froze it, and it
# stays frozen. Prints the alert's ID.
expect_frozen() {
  local pid=$1 out=$2 what=$3 a id
  a=$(wait_alert ".process.pid == $pid") || fail "$what: no alert for pid $pid"
  id=$(field "$a" .id)
  [ "$(field "$a" .tier)" = critical ] || fail "$what: alert $id is $(field "$a" .tier), want critical: $(field "$a" '.verdict.reasons[0]')"
  [ "$(field "$a" '[.actions[]? | select(.action=="freeze" and .ok)] | length')" -ge 1 ] || fail "$what: alert $id didn't freeze: $(field "$a" '.actions | tostring')"
  if [ -n "$out" ]; then frozen "$out" || fail "$what: pid $pid is still running"; fi
  note "$what: frozen $(field "$a" .latencyMs) ms after the open; $(field "$a" '.verdict.reasons[0]')" >&2
  echo "$id"
}

trap 'cleanup' EXIT

# =====================================================================
say "Before: nothing installed"
[ -e "$PLIST" ] && fail "ABA is already installed on this Mac: this test is for a throwaway one"
command -v jq >/dev/null || fail "jq is needed"
csrutil status | grep -q disabled || fail "System Integrity Protection is on: this test needs a throwaway Mac with it off (it writes the privacy database)"
mkdir -p "$HOME/Documents" "$HOME/Downloads"
"$ABA_BIN" --version || fail "the binary doesn't run"
sw_vers | sed 's/^/      /'

# Full Disk Access is a switch only the person at the screen can flip. On a
# throwaway Mac with System Integrity Protection off, root can write it into
# the privacy database directly, ahead of the install.
sudo sqlite3 "$TCCDB" "INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, flags, last_modified) VALUES ('kTCCServiceSystemPolicyAllFiles', '$LABEL', 0, 2, 4, 1, 'UNUSED', 0, CAST(strftime('%s','now') AS INTEGER));" \
  || fail "couldn't write the privacy database"
ok "Full Disk Access granted ahead of the install, in the privacy database"

# =====================================================================
say "Install"
sudo "$ABA_BIN" install --yes --preset balanced --learning 0 --auto-update=false || fail "aba install"
check "the daemon is running" test -n "$(service_pid)"
check "it's watching the baits (it has Full Disk Access)" test "$(sudo cat "$DATA/watching" 2>/dev/null)" = "$(service_pid)"
check "aba is on the PATH" test "$(readlink /usr/local/bin/aba)" = "$PROG/aba"
check "the program belongs to root" test "$(stat -f '%Su %Lp' "$PROG/famsvc")" = "root 755"
check "the app bundle is signed" codesign --verify "$SUPPORT/File Access Monitor.app"
check "state can't be read without root" bash -c "! cat '$DATA/state.json' >/dev/null 2>&1"
check "alerts can't be listed without root" bash -c "! ls '$DATA/alerts' >/dev/null 2>&1"
check "the log can't be read without root" bash -c "! cat '$DATA/service.log' >/dev/null 2>&1"
check "secrets are root's alone" test "$(sudo stat -f '%Su %Lp' "$DATA/secrets.json")" = "root 600"
wait_until 150 bash -c "aba status --once 2>/dev/null | grep -q Protected" || { aba status --once; fail "the dashboard (without root) doesn't say Protected"; }
ok "the dashboard says Protected, without root"
aba status --once | sed 's/^/      /'
sudo aba doctor | sed 's/^/      /'
has "Watching baits" sudo aba doctor || fail "aba doctor doesn't report on watching baits"

# The phone is a stand-in on this Mac (ntfy.sh has a daily quota per address).
launch "$GRABBER" -serve "$PHONE" -out "$OUT/phone" >/dev/null
printf '{"phone":{"kind":"ntfy","ntfy":{"server":"http://%s","topic":"aba-e2e"}},"canary":{}}' "$PHONE" | base64 | tr -d '\n' | sudo tee "$DATA/secrets.json" >/dev/null
sudo chmod 600 "$DATA/secrets.json"
r=$(reloads); sudo kill -HUP "$(service_pid)" || fail "couldn't tell the service to reload"; wait_reloaded "$r"
sudo aba phone test || fail "aba phone test"
wait_until 50 has_line 'POST /aba-e2e | A Better Antivirus test alert' "$OUT/phone" || fail "the test alert didn't reach the phone: $(cat "$OUT/phone" 2>/dev/null)"
ok "aba phone test reached the phone"

sudo aba bait list | sed 's/^/      /'
# This runner doesn't keep Desktop and Documents in iCloud, so nothing was
# asked and those baits are planted like the rest.
for id in desktop-passwords documents-passwords seed-phrase; do
  f=$(bait_file "$id"); [ -n "$f" ] && [ -f "$f" ] || fail "bait $id wasn't planted ($f)"
done
ok "baits on the Desktop and in Documents too"
check "the real AWS credentials file isn't faked" test ! -e "$HOME/.aws/credentials"
PASSWORDS=$(bait_file home-passwords)
EXODUS=$(bait_file exodus)
[ -n "$PASSWORDS" ] && [ -n "$EXODUS" ] || fail "the home-folder password list and the Exodus wallet weren't planted"
check "baits belong to the user" test "$(stat -f %Su "$PASSWORDS")" = "$ME"

# =====================================================================
say "aba test"
sudo aba test > "$OUT/test.txt" 2>&1 || { cat "$OUT/test.txt"; fail "aba test"; }
sed 's/^/      /' "$OUT/test.txt"
grep -q "Frozen" "$OUT/test.txt" || fail "aba test didn't freeze the fake stealer"
ok "aba test caught and froze its fake stealer"

# =====================================================================
say "A fake stealer opens a bait"
cp "$GRABBER" "$HOME/Downloads/free-game"; chmod 755 "$HOME/Downloads/free-game"
pid=$(launch "$HOME/Downloads/free-game" -child -wait 1000 -out "$OUT/s1" "$EXODUS")
id=$(expect_frozen "$pid" "$OUT/s1" "fake stealer") || exit 1
ok "frozen (alert $id)"
child=$(cat "$OUT/s1.child")
state | jq -e "[.frozen[].pid] | index($child)" >/dev/null || fail "the process it had started (pid $child) isn't frozen"
ok "the process it had started is frozen too"
kill -CONT "$pid" 2>/dev/null
check "still frozen after its own user's SIGCONT" frozen "$OUT/s1"
wait_until 200 sudo grep -q "phone alert sent for $id" "$DATA/service.log" || fail "the phone alert for $id didn't go out"
wait_until 25 has_line 'POST /aba-e2e | .*free-game' "$OUT/phone" || fail "the alert didn't reach the phone: $(cat "$OUT/phone" 2>/dev/null)"
ok "the phone got the alert: $(grep 'free-game' "$OUT/phone" | head -1 | cut -c1-150)"
sudo aba alerts | sed 's/^/      /'
sudo aba alerts show "$id" | sed 's/^/      /'
has "frozen" aba status --once || fail "the dashboard doesn't show that something is frozen"

say "aba kill"
sudo aba kill "$id" || fail "aba kill"
wait_until 25 gone "$pid" || fail "pid $pid survived aba kill"
wait_until 25 gone "$child" || fail "the stealer's helper survived aba kill"
ok "the stealer and what it started are gone"

# =====================================================================
say "A tool with nothing suspicious behind it is let through"
launch /bin/cat "$PASSWORDS" >/dev/null
a=$(wait_alert '((.process.image // "") | test("/cat$")) and .tier == "warn"') || fail "no warning for cat reading the bait"
[ "$(field "$a" '[.actions[]? | select(.action=="freeze")] | length')" = 0 ] || fail "ABA froze cat: $(field "$a" '.actions | tostring')"
ok "cat, started in the background: a warning, not frozen ($(field "$a" '.verdict.reasons[0]'))"

say "The same tool, run by a script from Downloads"
cat > "$HOME/Downloads/install.sh" <<'EOF'
#!/bin/sh
cat "$1" > /dev/null
while :; do echo . >> "$2.tick"; sleep 0.1; done
EOF
chmod +x "$HOME/Downloads/install.sh"
spid=$(launch /bin/sh "$HOME/Downloads/install.sh" "$PASSWORDS" "$OUT/sh1")
echo "$spid" > "$OUT/sh1.pid"
a=$(wait_alert '.tier == "critical" and ((.verdict.reasons[0] // "") | test("install.sh"))') || fail "cat run by a script from Downloads wasn't critical"
id=$(field "$a" .id)
check "the script is frozen ($(field "$a" '.verdict.reasons[0]'))" frozen "$OUT/sh1"
sudo aba kill "$id" >/dev/null || fail "aba kill"
rm -f "$HOME/Downloads/install.sh"

# =====================================================================
say "aba resume"
pid=$(launch "$HOME/Downloads/free-game" -wait 1000 -out "$OUT/s2" "$EXODUS")
id=$(expect_frozen "$pid" "$OUT/s2" "fake stealer") || exit 1
sudo aba resume "$id" || fail "aba resume"
wait_until 50 running "$OUT/s2" || fail "the resumed program didn't carry on"
check "nothing is left on record as frozen" test "$(state | jq '.frozen | length')" = 0
kill -9 "$pid" 2>/dev/null

say "aba trust"
pid=$(launch "$HOME/Downloads/free-game" -wait 1000 -out "$OUT/s3" "$EXODUS")
id=$(expect_frozen "$pid" "$OUT/s3" "fake stealer") || exit 1
r=$(reloads)
sudo aba trust "$id" || fail "aba trust"
wait_reloaded "$r"
wait_until 50 running "$OUT/s3" || fail "the trusted program didn't carry on"
kill -9 "$pid" 2>/dev/null
count=$(alerts | jq length)
pid=$(launch "$HOME/Downloads/free-game" -wait 500 -out "$OUT/s4" "$EXODUS")
wait_until 50 has_line '^DONE' "$OUT/s4" || fail "a trusted program didn't get to read"
sleep 2
check "a trusted program reads that bait and keeps running" running "$OUT/s4"
check "… without a new alert" test "$(alerts | jq length)" = "$count"
kill -9 "$pid" 2>/dev/null
sudo aba ignore list | sed 's/^/      /'

say "aba release"
cp "$GRABBER" "$HOME/Downloads/other-game"; echo "different file, different fingerprint" >> "$HOME/Downloads/other-game"; codesign --force -s - "$HOME/Downloads/other-game" 2>/dev/null; chmod 755 "$HOME/Downloads/other-game"
p1=$(launch "$HOME/Downloads/other-game" -wait 1000 -out "$OUT/r1" "$PASSWORDS")
expect_frozen "$p1" "$OUT/r1" "first" >/dev/null || exit 1
p2=$(launch "$HOME/Downloads/other-game" -wait 1000 -out "$OUT/r2" "$(bait_file ssh-key)")
expect_frozen "$p2" "$OUT/r2" "second" >/dev/null || exit 1
sudo aba release || fail "aba release"
wait_until 50 running "$OUT/r1" && wait_until 50 running "$OUT/r2" || fail "aba release didn't let both run again"
check "nothing is left on record as frozen" test "$(state | jq '.frozen | length')" = 0
kill -9 "$p1" "$p2" 2>/dev/null
ok "everything frozen runs again"

# =====================================================================
say "A sweep: one of Apple's tools going through several apps' data"
# (The program is given on the command line: a script in a folder you can
# write to would be critical by itself.)
SWEEP='import sys, time
for p in sys.argv[2:]:
    open(p, "rb").read()
while True:
    open(sys.argv[1] + ".tick", "a").write(".\n"); time.sleep(0.1)'
pid=$(launch /usr/bin/python3 -c "$SWEEP" "$OUT/sw" "$(bait_file vivaldi)" "$(bait_file electrum)" "$(bait_file ssh-key)" "$EXODUS")
echo "$pid" > "$OUT/sw.pid"
a=$(wait_alert ".process.pid == $pid and .tier == \"critical\"") || fail "a sweep wasn't critical"
note "$(field "$a" '.verdict.reasons[0]')"
alive "$pid" || { output "$pid"; fail "python exited by itself"; }
check "frozen" frozen "$OUT/sw"
sudo aba kill "$(field "$a" .id)" >/dev/null || fail "aba kill"

say "A hard-link trick"
LINK='import os, sys, time
os.link(sys.argv[2], sys.argv[1] + ".lnk"); open(sys.argv[1] + ".lnk", "rb").read()
while True:
    open(sys.argv[1] + ".tick", "a").write(".\n"); time.sleep(0.1)'
pid=$(launch /usr/bin/python3 -c "$LINK" "$OUT/hl" "$PASSWORDS")
echo "$pid" > "$OUT/hl.pid"
a=$(wait_alert ".process.pid == $pid and .tier == \"critical\"") || fail "reading a bait through a hard link wasn't critical"
note "$(field "$a" '.verdict.reasons[0]')"
alive "$pid" || { output "$pid"; fail "python exited by itself"; }
check "frozen" frozen "$OUT/hl"
sudo aba kill "$(field "$a" .id)" >/dev/null || fail "aba kill"
rm -f "$OUT/hl.lnk"

# =====================================================================
say "A copy made by Finder, for a fake stealer"
pid=$(launch "$HOME/Downloads/free-game" -finder -wait 1000 -out "$OUT/f1" "$PASSWORDS")
if a=$(wait_alert ".process.pid == $pid"); then
  [ "$(field "$a" .tier)" = critical ] || fail "the copy through Finder is $(field "$a" .tier): $(field "$a" '.verdict.reasons | tostring')"
  check "the fake stealer behind the copy is frozen" frozen "$OUT/f1"
  sudo grep "copied by Finder's helper" "$DATA/service.log" | tail -1 | sed 's/^/      /'
  # Finder's helper is frozen with it if it's still copying; a small file is
  # usually copied before the event arrives, and then there's no helper left.
  if field "$a" '[.actions[]? | select(.action=="freeze") | .detail] | join(" ")' | grep -q DesktopServicesHelper; then
    ok "Finder's helper was frozen with it, mid-copy"
  else
    note "Finder's helper had finished the copy before the freeze: $(field "$a" '[.actions[]? | select(.action=="freeze") | .detail] | join(" ")')"
  fi
  sudo aba kill "$(field "$a" .id)" >/dev/null
else
  sudo grep -E "Finder|DesktopServices" "$DATA/service.log" | tail -5 | sed 's/^/      /'
  cat "$OUT/f1" 2>/dev/null | sed 's/^/      /'
  fail "no alert for the fake stealer that had Finder copy a bait"
fi

say "An ordinary copy through Finder is left alone"
mkdir -p "$OUT/plain"
launch /usr/bin/osascript -e "tell application \"Finder\" to duplicate (POSIX file \"$PASSWORDS\" as alias) to folder (POSIX file \"$OUT/plain\" as alias) with replacing" >/dev/null
a=$(wait_alert '((.process.image // "") | test("osascript$"))') || fail "no record of osascript having Finder copy the bait"
[ "$(field "$a" .tier)" != critical ] || fail "an AppleScript one-liner having Finder copy a file is critical: $(field "$a" '.verdict.reasons | tostring')"
[ "$(field "$a" '[.actions[]? | select(.action=="freeze")] | length')" = 0 ] || fail "ABA froze something for an ordinary copy: $(field "$a" '.actions | tostring')"
ok "a $(field "$a" .tier), nothing frozen ($(field "$a" '.verdict.reasons[0]'))"

# =====================================================================
say "Strict mode: the whole Mac is cut off, and given back"
r=$(reloads)
sudo sh -c "jq '.responses.critical = [\"freeze\",\"block-program\",\"isolate\"]' '$DATA/config.json' > '$DATA/config.new' && mv '$DATA/config.new' '$DATA/config.json'"
sudo kill -HUP "$(service_pid)"
wait_reloaded "$r"
curl -s -m 10 -o /dev/null https://www.apple.com || fail "no internet to begin with"
# (other-game: free-game is trusted with the Exodus wallet by now.)
pid=$(launch "$HOME/Downloads/other-game" -wait 1000 -out "$OUT/i1" "$EXODUS")
a=$(wait_alert ".process.pid == $pid and ([.actions[]? | select(.action==\"isolate\")] | length) > 0") || fail "no isolation"
[ "$(field "$a" '[.actions[]? | select(.action=="isolate" and .ok)] | length')" = 1 ] || fail "isolation failed: $(field "$a" '.actions | tostring')"
curl -s -m 5 -o /dev/null https://www.apple.com && fail "the Mac still reaches the internet"
ok "isolated: nothing gets out"
sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null | sed 's/^/      /'
sudo aba release || fail "aba release"
curl -s -m 10 -o /dev/null https://www.apple.com || fail "the internet didn't come back after aba release"
check "pf has no rules of ABA's left" test -z "$(sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null)"
ok "aba release gave the internet back"
kill -9 "$pid" 2>/dev/null

# =====================================================================
say "Uninstall"
BAIT_FILES=(); while IFS= read -r f; do BAIT_FILES+=("$f"); done < <(state | jq -r '.baits[].files[].path')
sudo aba uninstall --purge || fail "aba uninstall"
check "no daemon" test ! -e "$PLIST"
check "launchd doesn't know it" bash -c "! launchctl print system/$LABEL >/dev/null 2>&1"
check "no program" test ! -e "$SUPPORT/File Access Monitor.app"
check "no data" test ! -e "$DATA"
check "no aba on the PATH" test ! -e /usr/local/bin/aba
for f in "${BAIT_FILES[@]}"; do [ -e "$f" ] && fail "bait left behind: $f"; done
ok "every bait is gone (${#BAIT_FILES[@]} files)"
check "no pf rules" test -z "$(sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null)"
say "All good"
