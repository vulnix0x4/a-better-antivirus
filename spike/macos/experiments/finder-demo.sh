#!/bin/bash
# The Atomic-style case: a harmless fake stealer has *Finder* copy the bait
# (AppleScript "tell application Finder to duplicate"), so the process that
# opens the file is Apple's DesktopServicesHelper. Does the watcher still find
# and freeze the fake stealer?
#
# Run as the ordinary user, from a terminal that is allowed to control Finder
# (System Settings > Privacy & Security > Automation), while the spike daemon
# is installed and has Full Disk Access:
#
#   experiments/finder-demo.sh [runs]
set -u
RUNS=${1:-5}
cd "$(dirname "$0")/.."
D=/Users/Shared/aba-spike-finder
STEALER="/Library/Application Support/ABA Spike/ABA Spike.app/Contents/Resources/fake-stealer"
rm -rf "$D"; mkdir -p "$D/Documents/loot" "$D/Downloads" "$D/stage"
BAIT="$D/Documents/passwords.txt"
echo "bank: hunter2 (fake, planted by aba-spike)" > "$BAIT"
for i in $(seq 40); do printf 'made-up loot %s\n' $i > "$D/Documents/loot/f$i.txt"; done
HITS=/var/db/aba-spike/out/finder-hits.jsonl
JOB=finderwatch-$$
if [ -n "${SPIKE_PW:-}" ]; then
	sudo -S -p '' experiments/local-daemon.sh job $JOB watch -bait "$BAIT" -action stop -seconds $((RUNS * 12 + 20)) -json $HITS < "$SPIKE_PW"
else
	sudo experiments/local-daemon.sh job $JOB watch -bait "$BAIT" -action stop -seconds $((RUNS * 12 + 20)) -json $HITS
fi
sleep 4
start_lines=$(cat $HITS 2>/dev/null | wc -l)
for i in $(seq "$RUNS"); do
	rm -f "$D/stage/passwords.txt"
	EXE="$D/Downloads/FreeGameInstaller-$i"
	cp "$STEALER" "$EXE"
	nohup "$EXE" -how finder -bait "$BAIT" -loot "$D/Documents/loot" -stage "$D/stage" -rate 500 \
		-stamp "$D/stamp-$i" -log "$D/steps-$i.jsonl" > /dev/null 2>&1 &
	P=$!
	sleep 3
	a=$(od -An -tu8 -N8 "$D/stamp-$i" 2>/dev/null | tr -d ' ')
	sleep 0.5
	b=$(od -An -tu8 -N8 "$D/stamp-$i" 2>/dev/null | tr -d ' ')
	copied=no; [ -f "$D/stage/passwords.txt" ] && copied=yes
	state=$(ps -o state= -p $P 2>/dev/null | tr -d ' ')
	python3 - "$HITS" "$start_lines" "$P" "$D/steps-$i.jsonl" "$i" "$a" "$b" "$copied" "$state" <<'EOF'
import json, sys
hits, skip, pid, steps, run, a, b, copied, state = sys.argv[1:]
lines = open(hits).read().splitlines()[int(skip):]
mine = [json.loads(l) for l in lines]
mine = [h for h in mine if pid in [str(x) for x in (h.get("stopped_pids") or [])] or ("[%s]" % pid) in " ".join(h.get("chain") or [])]
st = {}
for l in open(steps):
    m = json.loads(l); st[m["step"]] = m["t_unix_nano"]
import datetime, re
def t(s):
    m = re.match(r"(.*T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$", s or "")
    if not m or s.startswith("0001"): return None
    base = datetime.datetime.fromisoformat(m.group(1) + ("+00:00" if m.group(3) == "Z" else m.group(3)))
    return base.timestamp() * 1e9 + float("0" + (m.group(2) or ".0")) * 1e9
if not mine:
    print(f"run {run}: NOT CAUGHT (fake stealer pid {pid}, Finder copied the bait: {copied})")
    sys.exit()
h = mine[0]
pre = st.get("pre_open")
ev, act = t(h["t_event"]), t(h["t_acted"])
if act is None: act = ev
frozen = a == b and a != ""
print(f"run {run}: opener={h['opener']['Path'].split('/')[-1]} severity={h['severity']} stopped={h['stopped_pids']} fake-stealer frozen={frozen} (state {state})")
print(f"        chain: {' <- '.join(h['chain'])}   (found via {h.get('finder_via')}; Finder's log line arrived {h.get('finder_log_lag_ms', '-')} ms after it was written)")
print(f"        script started -> helper opened bait {(ev-pre)/1e6:.0f} ms, -> asker frozen {(act-pre)/1e6:.0f} ms (open -> frozen {(act-ev)/1e6:.1f} ms); Finder finished the copy: {copied}")
EOF
	kill -9 $P 2>/dev/null; pkill -9 -f "duplicate \(POSIX file \"$BAIT" 2>/dev/null
	wait $P 2>/dev/null
	rm -f "$EXE"
	sleep 2
done
for i in $(seq 120); do [ -f /var/db/aba-spike/out/$JOB.done ] && break; sleep 1; done
grep -h "Finder log lines" /var/db/aba-spike/out/$JOB.log
rm -rf "$D"
