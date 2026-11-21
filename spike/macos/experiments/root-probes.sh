#!/bin/bash
# Things only root can try, none of which need Full Disk Access.
# Usage: sudo experiments/root-probes.sh <uid of an ordinary user>
#
# Harmless: the only processes it touches are spinners it starts itself.
set -u
U=${1:?uid of an ordinary user}
cd "$(dirname "$0")/.."
B=build/exp
mkdir -p "$B"
chmod 755 build "$B"
for c in lease susp spin sockets; do cc -w -o "$B/$c" "experiments/c/$c.c" || exit 1; done
W=$(mktemp -d /tmp/aba-probes.XXXXXX)
chmod 755 "$W"
chown "$U" "$W"
asuser() { sudo -u "#$U" "$@"; }
moving() { # is the spinner's heartbeat advancing?
	a=$(cut -d' ' -f1 "$W/hb.txt"); sleep 0.3; b=$(cut -d' ' -f1 "$W/hb.txt")
	[ "$a" = "$b" ] && echo "      => FROZEN" || echo "      => running"
}
spinner() { asuser "$B/spin" "$W/hb.txt" & sleep 0.5; P=$(pgrep -n -u "$U" spin); }

echo "### 1. Endpoint Security client, as root, without the entitlement"
if [ -x build/esnative ]; then build/esnative; else echo "(build/esnative not built)"; fi

echo
echo "### 2. File lease (the nearest thing to a Windows oplock), as root"
echo secret > "$W/bait.txt"
"$B/lease" "$W/bait.txt" 3 300

echo
echo "### 3. Suspending a process of user $U so that the user cannot undo it"
spinner
echo "  a. root SIGSTOP, then the user sends SIGCONT"
kill -STOP "$P"; moving
asuser "$B/susp" cont "$P"; moving
echo "  b. root pid_suspend, then the user tries SIGCONT and pid_resume"
"$B/susp" pid_suspend "$P"; moving
asuser "$B/susp" cont "$P"; moving
asuser "$B/susp" pid_resume "$P"; moving
echo "     root pid_resume"
"$B/susp" pid_resume "$P"; moving
echo "  c. root task_for_pid + task_suspend, then the user tries SIGCONT and task_resume"
"$B/susp" task_suspend "$P"; moving
asuser "$B/susp" cont "$P"; moving
asuser "$B/susp" task_resume "$P"; moving
"$B/susp" task_resume "$P"; moving
echo "  d. root SIGSTOP and re-send it every 1 ms; the user sends SIGCONT 200 times"
kill -STOP "$P"
( while kill -STOP "$P" 2>/dev/null; do sleep 0.001; done ) &
LOOP=$!
n0=$(cut -d' ' -f1 "$W/hb.txt")
for i in $(seq 200); do asuser kill -CONT "$P"; done
n1=$(cut -d' ' -f1 "$W/hb.txt")
kill $LOOP 2>/dev/null
echo "      spinner iterations (2 ms each) that got through 200 SIGCONTs: $((n1 - n0))"
kill -9 "$P"

echo
echo "### 4. Cutting one process's connections: pid_shutdown_sockets as root"
spinner
"$B/sockets" "$P"
kill -9 "$P"

echo
echo "### 5. Other ways to see an open, without Endpoint Security"
echo "  a. fs_usage (kernel trace; one tracer at a time)"
( fs_usage -w -f pathname 2>&1 | grep --line-buffered "aba-probes" > "$W/fsusage.txt" ) &
sleep 2
T0=$(python3 -c 'import time; print(time.time())')
asuser /bin/cat "$W/bait.txt" > /dev/null
sleep 2
pkill -x fs_usage
head -3 "$W/fsusage.txt" | cut -c1-200
echo "      (cat ran at $(python3 -c "import time; print(time.strftime('%H:%M:%S', time.localtime($T0)) + ('%.6f' % ($T0 % 1))[1:])"))"
echo "  b. OpenBSM audit (deprecated since macOS 11)"
ls -la /dev/auditpipe 2>&1
audit -c 2>&1 | head -2 || true
[ -f /etc/security/audit_control ] && echo "      audit_control present" || echo "      /etc/security/audit_control absent: auditing is not configured"
launchctl print system/com.apple.auditd 2>&1 | grep -E "state|disabled" | head -3
echo "  c. dtrace with System Integrity Protection on"
( dtrace -q -n 'syscall::open:entry /execname == "cat"/ { printf("dtrace saw %s open %s\n", execname, copyinstr(arg0)); }' > "$W/dtrace.txt" 2>&1 ) &
sleep 3
asuser /bin/cat "$W/bait.txt" > /dev/null
"$B/spin" /dev/null & SP=$!; sleep 0.2; kill $SP
sleep 1
pkill -x dtrace
head -4 "$W/dtrace.txt" | cut -c1-200
echo "      (dtrace lines above: none means it saw nothing)"

echo
echo "### 6. A root daemon talking to the logged-in user"
CU=$(stat -f %u /dev/console)
echo "  console user uid: $CU"
launchctl asuser "$CU" /usr/bin/osascript -e 'display notification "Test notification from a root process (ABA spike)" with title "ABA spike"' 2>&1 | head -2
echo "      display notification exit: $?"
R=$(launchctl asuser "$CU" /usr/bin/osascript -e 'display dialog "ABA spike: can a root daemon ask you a question?\n\nThis closes by itself in 5 seconds." with title "ABA spike" buttons {"Kill it", "It is mine"} default button 1 giving up after 5' 2>&1)
echo "      display dialog via launchctl asuser: $R"

rm -rf "$W"
