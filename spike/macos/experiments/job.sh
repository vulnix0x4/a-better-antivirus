#!/bin/bash
# Developer convenience: run one aba-spike command inside the installed spike
# daemon and print its output. Usage: job.sh NAME TIMEOUT_SECONDS ARGS...
# Reads the sudo password from the file named in $SPIKE_PW if set.
N=$1; T=$2; shift 2
cd "$(dirname "$0")/.."
if [ -n "${SPIKE_PW:-}" ]; then sudo -S -p '' experiments/local-daemon.sh job "$N" "$@" < "$SPIKE_PW"; else sudo experiments/local-daemon.sh job "$N" "$@"; fi
for i in $(seq $((T * 5))); do [ -f "/var/db/aba-spike/out/$N.done" ] && break; sleep 0.2; done
cat "/var/db/aba-spike/out/$N.log"
