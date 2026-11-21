# Security policy

A Better Antivirus runs as SYSTEM, so bugs in it matter. Please report vulnerabilities privately through
GitHub's [Report a vulnerability](https://github.com/vulnix0x4/a-better-antivirus/security/advisories/new)
(Security tab) rather than a public issue. You'll get a reply within a few days.

Especially interesting:

- ways for a non-admin process to disable, blind or bypass A Better Antivirus (stop the service, strip audit
  rules, get ignored, undo a response, read secrets),
- ways to make the SYSTEM service run attacker-controlled code or touch attacker-chosen files,
- ways to get the auto-updater to install something that wasn't signed with the release key,
- ways for a stealer to tell baits apart from real data cheaply.

Out of scope: attacks that already require administrator rights (see "Honest limitations" in the README).

## What a program running as you must not be able to do

These are the lines ABA is built to hold against malware without admin rights. A way across any of them
is a vulnerability:

- **Learn where the baits are** from ABA itself. `C:\ProgramData\FileAccessMonitor` is readable by SYSTEM and
  administrators only; the one world-readable file, `public\status.json`, holds health and counts, never a
  path, a bait name, a program name, an alert or how ABA is set to respond.
- **Keep the service busy or tell it what to do.** Only SYSTEM and administrators can send it commands.
- **Read a bait without an alert.** Baits are recognised by the file, not its name (hard links), the audit
  rule covers read *and* execute access (memory mappings), and an open that refuses to be paused is
  attributed by the handle it holds.
- **Get a bait removed.** Decoys are only retired for an app signed by its publisher, loudly, and one a day.
- **Avoid or undo the freeze.** Protected Windows processes are recognised by their real path, the processes
  around the reader are frozen with it, and frozen processes are held in a nameless job object only the
  service has a handle to.
- **Pass for something trusted:** a renamed or swapped executable, a copy of ABA, a signed program carrying
  an unsigned DLL, a sweep split across processes, a scheduled task in session 0.
- **Get code run with more rights** through anything ABA starts or writes.

`internal/engine/bypass_test.go`, `internal/instant/ghost_test.go` and the *Evasion* step of
`scripts/e2e.ps1` each replay one of these. A new bypass report is most useful as one more test there.

## How releases and updates are protected

- Releases are built by GitHub Actions from a tagged commit ([release.yml](.github/workflows/release.yml)).
- Every release ships `SHA256SUMS.txt` and `SHA256SUMS.txt.sig`: an ed25519 signature over the checksum list,
  made with the release key. The public key is compiled into ABA ([internal/update](internal/update/update.go)).
- The auto-updater (and `aba update`) only installs a release whose signature verifies and whose `.exe` matches
  the signed hash. It refuses downgrades, pre-releases and downloads from anywhere but GitHub, and rolls back
  if the new version fails to start.
- Updates are downloaded into `C:\Program Files\File Access Monitor\updates`, which only administrators and
  SYSTEM can write to.

Supported versions: the latest release.
