# macOS spike

A throwaway prototype and the experiments behind the macOS recommendation. **This is not the port.**
It is its own Go module so the Windows build, tests and CI never see it. What was measured, and what
is recommended, is in the pull request that added this folder.

## What is here

| | |
|---|---|
| `cmd/aba-spike` | The prototype. `demo` plants a bait, runs the fake stealer as an ordinary user, catches it through Apple's `eslogger`, names it, freezes it and prints the delays. `watch`, `capture`, `cpu`, `storm`, `sig`, `fda` are the measuring tools. |
| `cmd/fake-stealer` | The harmless test program: opens the bait, then keeps reading made-up files next to it and writes down how far it got. No network, nothing outside the folder it is given. |
| `experiments/root-probes.sh` | What root can and cannot do without Full Disk Access: an Endpoint Security client without the entitlement, file leases, three ways to suspend a process and who can undo each, `fs_usage`, dtrace, auditing, a dialog from a root process. |
| `experiments/pf-isolate.sh` | Cuts one user's internet, then the whole Mac's, with pf, while a root process still reaches the alert server. Always cleans up. |
| `experiments/readers.sh` | Sixteen ways to get at a file (cat, cp, clone, zip, Python, AppleScript, Finder duplicate…), each on its own bait, to see what the kernel reports for each. |
| `experiments/finder-demo.sh` | The Atomic-style case: the fake stealer has Finder copy the bait, so Apple's `DesktopServicesHelper` opens it. Checks that the watcher still finds and freezes the fake stealer (it follows Finder's log for who has been sending it Apple events). |
| `experiments/soak.sh` | Plants fake baits where macOS stealers look, to record which legitimate software reads them. |
| `experiments/local-daemon.sh`, `job.sh` | Installs the prototype the way the product would be installed (an app-like bundle run by a LaunchDaemon), so that it can be granted Full Disk Access, and runs commands inside it. |
| `experiments/esnative` | A cgo program that asks for a native Endpoint Security client, to show what happens without Apple's entitlement. |
| `experiments/c` | Small C programs used by the scripts. |

## Running it

On GitHub's macOS runners everything runs as is (`.github/workflows/macos-spike.yml`): they have
passwordless sudo and Full Disk Access for the shell.

On your own Mac, `eslogger` needs root **and** Full Disk Access for the program responsible for it.
From a terminal that program is the terminal app; the cleaner way is the spike daemon:

```sh
cd spike/macos
SPIKE_SIGN_ID="Apple Development: …" experiments/local-daemon.sh bundle   # or leave unset for ad-hoc
sudo experiments/local-daemon.sh install $(id -u)
# System Settings > Privacy & Security > Full Disk Access: switch on "ABA Spike"
experiments/job.sh demo 120 demo -runs 20 -rate 500 -uid $(id -u) -gid $(id -g) \
    -stealer "/Library/Application Support/ABA Spike/ABA Spike.app/Contents/Resources/fake-stealer"
sudo experiments/local-daemon.sh uninstall
```

`root-probes.sh` and `pf-isolate.sh` only need `sudo`. `pf-isolate.sh` takes the Mac offline for a
few seconds.

Never point any of this at real malware. The fake stealer is the only thing it is meant to catch.
