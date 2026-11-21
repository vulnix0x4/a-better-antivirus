#!/bin/bash
# Things only root can try, none of which need Full Disk Access.
# Usage: sudo experiments/root-probes.sh <uid of an ordinary user> ["1 2 3 4 5 6"]  (sections to run)
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
# run something with a time limit (macOS has no timeout(1))
limit() { perl -e 'alarm shift; exec @ARGV or die' "$@"; }
moving() { # is the spinner's heartbeat advancing?
	a=$(cut -d' ' -f1 "$W/hb.txt"); sleep 0.3; b=$(cut -d' ' -f1 "$W/hb.txt")
	[ "$a" = "$b" ] && echo "      => FROZEN" || echo "      => running"
}
spinner() {
	asuser "$B/spin" "$W/hb.txt" > /dev/null 2>&1 &
	sleep 0.5
	P=$(pgrep -n -u "$U" -x spin)
	if [ -z "$P" ]; then echo "could not start the spinner"; exit 1; fi
}

SECTIONS=${2:-1 2 3 4 5 6}
want() { case " $SECTIONS " in *" $1 "*) return 0;; esac; return 1; }
if want 1; then
	echo "### 1. Endpoint Security client, as root, without the entitlement"
	if [ -x build/esnative ]; then build/esnative; else echo "(build/esnative not built)"; fi

	echo
fi
if want 2; then
	echo "### 2. File lease (the nearest thing to a Windows oplock), as root"
	echo secret > "$W/bait.txt"
	"$B/lease" "$W/bait.txt" 3 300

	echo
fi
if want 3; then
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
	echo "     pid_suspend again, then the user sends SIGKILL"
	"$B/susp" pid_suspend "$P"
	asuser kill -KILL "$P"; sleep 0.3
	kill -0 "$P" 2>/dev/null && echo "      => still there" || echo "      => gone: a suspended process can still be killed"
	spinner
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
fi
if want 4; then
	echo "### 4. Cutting one process's connections: pid_shutdown_sockets as root"
	spinner
	"$B/sockets" "$P"
	kill -9 "$P"

	echo
fi
if want 5; then
	echo "### 5. Other ways to see an open, without Endpoint Security"
	echo "  a. fs_usage (kernel trace; one tracer at a time)"
	( limit 12 fs_usage -w -f pathname 2>&1 | grep --line-buffered "bait.txt" | while IFS= read -r l; do echo "$(python3 -c 'import time; t=time.time(); print(time.strftime("%H:%M:%S", time.localtime(t)) + ("%.3f" % (t % 1))[1:])') got: $l"; done > "$W/fsusage.txt" ) &
	sleep 3
	C0=$(ps -o cputime= -p "$(pgrep -x fs_usage | head -1)" 2>/dev/null)
	echo "      cat runs at $(python3 -c 'import time; t=time.time(); print(time.strftime("%H:%M:%S", time.localtime(t)) + ("%.3f" % (t % 1))[1:])')"
	asuser /bin/cat "$W/bait.txt" > /dev/null
	sleep 5
	echo "      fs_usage CPU time used in ~8 s of watching the whole system: $(ps -o cputime= -p "$(pgrep -x fs_usage | head -1)" 2>/dev/null)"
	pkill -x fs_usage
	sleep 1
	grep -E "open|read" "$W/fsusage.txt" | head -3 | tr -s ' ' | cut -c1-230
	echo "  b. OpenBSM audit (deprecated since macOS 11)"
	ls -la /dev/auditpipe 2>&1
	audit -c 2>&1 | head -2 || true
	[ -f /etc/security/audit_control ] && echo "      audit_control present" || echo "      /etc/security/audit_control absent: auditing is not configured"
	launchctl print system/com.apple.auditd 2>&1 | grep -E "state|disabled" | head -3
	echo "  c. dtrace with System Integrity Protection on"
	( limit 8 dtrace -q -n 'syscall::open:entry /execname == "cat"/ { printf("dtrace saw %s open %s\n", execname, copyinstr(arg0)); }' > "$W/dtrace.txt" 2>&1 ) &
	sleep 3
	asuser /bin/cat "$W/bait.txt" > /dev/null
	sleep 1
	pkill -x dtrace
	head -4 "$W/dtrace.txt" | cut -c1-200
	echo "      (dtrace lines above: none means it saw nothing)"

	echo
fi
if want 6; then
	echo "### 6. A root daemon talking to the logged-in user"
	CU=$(stat -f %u /dev/console)
	echo "  console user uid: $CU"
	# Run each in the background and give up after a while: without a real
	# desktop session these can wait forever, and nothing may be left behind
	# holding this script's output open.
	bg() { # seconds, output file, command...
		t=$1; out=$2; shift 2
		"$@" > "$out" 2>&1 &
		bp=$!
		for i in $(seq $((t * 5))); do kill -0 $bp 2>/dev/null || break; sleep 0.2; done
		if kill -0 $bp 2>/dev/null; then kill -9 $bp 2>/dev/null; pkill -9 -x osascript 2>/dev/null; echo "(gave up after ${t} s)" >> "$out"; fi
		wait $bp 2>/dev/null
	}
	bg 15 "$W/n.txt" launchctl asuser "$CU" /usr/bin/osascript -e 'display notification "Test notification from a root process (ABA spike)" with title "ABA spike"'
	echo "      display notification via launchctl asuser: $(tr '\n' ' ' < "$W/n.txt" | cut -c1-200) [done]"
	bg 20 "$W/d.txt" launchctl asuser "$CU" /usr/bin/osascript -e 'display dialog "ABA spike: can a root daemon ask you a question?\n\nThis closes by itself in 5 seconds." with title "ABA spike" buttons {"Kill it", "It is mine"} default button 1 giving up after 5'
	echo "      display dialog via launchctl asuser: $(tr '\n' ' ' < "$W/d.txt" | cut -c1-200)"

fi
rm -rf "$W"
